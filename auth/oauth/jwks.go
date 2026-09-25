package oauth

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

const (
	// jwksTTL bounds how long a fetched key set is trusted before a refresh.
	jwksTTL = time.Hour
	// jwksMaxBytes caps a JWKS response so a hostile endpoint cannot exhaust memory.
	jwksMaxBytes = 1 << 20
	// minRefreshInterval throttles refreshes triggered by an unknown kid. Without
	// it, a flood of tokens carrying bogus kids would force one outbound JWKS GET
	// per verification (request amplification). A genuine key rotation is still
	// picked up within this window.
	minRefreshInterval = time.Minute
)

// jwk is one JSON Web Key. The fields that restrict the key (alg, use,
// key_ops) are kept here and enforced at selection time per RFC 7517 §4.3 and
// RFC 8725 §3.1.
type jwk struct {
	Kty    string   `json:"kty"`
	Kid    string   `json:"kid"`
	Use    string   `json:"use"`
	Alg    string   `json:"alg"`
	KeyOps []string `json:"key_ops"`
	N      string   `json:"n"` // RSA modulus (base64url)
	E      string   `json:"e"` // RSA exponent (base64url)
	Crv    string   `json:"crv"`
	X      string   `json:"x"` // EC x (base64url)
	Y      string   `json:"y"` // EC y (base64url)
}

type jwksDoc struct {
	Keys []jwk `json:"keys"`
}

// candidate is a parsed JWK paired with the metadata needed to enforce the
// per-key alg/use/key_ops restrictions at selection time. Two candidates may
// share a kid (RFC 7517 permits an RSA key and an EC key under one kid) and
// the verifier picks by token alg.
type candidate struct {
	pub    crypto.PublicKey
	alg    string
	use    string
	keyOps map[string]struct{}
}

// jwksCache fetches and caches a provider's signing keys. Per kid, the cache
// holds a slice of candidates so two providers sharing a kid (e.g. an RSA and
// an EC key) remain individually selectable; selection is driven by the
// token's kid and alg headers.
type jwksCache struct {
	url  string
	http *http.Client

	group singleflight.Group // collapses concurrent refreshes into one outbound fetch

	mu            sync.RWMutex
	keys          map[string][]candidate // kid -> candidates
	anonAvailable bool                   // true when the set has exactly one key with no kid
	expiresAt     time.Time
	lastAttempt   time.Time // last refresh attempt, to throttle unknown-kid-driven fetches

	// now returns the current time. Overridden in tests so the TTL can be
	// advanced without sleeping. Defaults to time.Now.
	now func() time.Time
}

func newJWKSCache(url string, h *http.Client) *jwksCache {
	return &jwksCache{
		url:  url,
		http: h,
		keys: make(map[string][]candidate),
		now:  time.Now,
	}
}

// key returns the public key for verifying a token whose header carries the
// given kid and alg. When kid is empty and the cached set has exactly one key
// with no kid, that key is returned (OIDC permits a JWKS of one key without
// a kid). The per-key alg/use/key_ops restrictions declared on the JWK are
// enforced here, so a key published with alg:"RS256" cannot verify a PS256
// token and a key published with key_ops:["encrypt"] cannot verify at all.
//
// It refreshes the cache when the entry is missing or stale, since refreshing
// on an unknown kid is how key rotation is picked up. If a refresh fails but
// the cached key set for kid is still inside its TTL, that set is used; once
// the TTL has passed, a failed refresh fails closed with ErrJWKSStale so a
// withdrawn key cannot outlive the outage.
func (c *jwksCache) key(ctx context.Context, kid, alg string) (crypto.PublicKey, error) {
	c.mu.RLock()
	candidates, ok := c.keys[kid]
	anonAvailable := c.anonAvailable
	expires := c.expiresAt
	lastAttempt := c.lastAttempt
	c.mu.RUnlock()

	now := c.now()
	if ok && now.Before(expires) {
		return pickCandidate(candidates, kid, alg)
	}

	// Skip an unknown kid only while a recent failed refresh is still inside
	// the cooldown. While another caller's refresh is in flight, lastAttempt
	// carries the previous attempt's timestamp, so concurrent callers join it
	// rather than being refused up front.
	if !ok && now.Sub(lastAttempt) < minRefreshInterval {
		return nil, fmt.Errorf("%w: unknown kid %q", ErrJWKS, kid)
	}

	// Collapse concurrent refreshes: a burst of tokens carrying distinct
	// unknown kids must produce a single outbound JWKS fetch, not one per
	// request.
	_, err, _ := c.group.Do(c.url, func() (any, error) { return nil, c.refresh(ctx) })
	if err != nil {
		if ok {
			if now.Before(expires) {
				return pickCandidate(candidates, kid, alg) // known set inside its TTL: serve it on a transient JWKS outage
			}
			// Past expiry: fail closed. A withdrawn key must not remain usable
			// while the provider is unreachable.
			return nil, fmt.Errorf("%w: %w", ErrJWKSStale, err)
		}
		return nil, err
	}

	c.mu.RLock()
	candidates, ok = c.keys[kid]
	anonAvailable = c.anonAvailable
	c.mu.RUnlock()
	if !ok {
		if kid == "" && anonAvailable {
			candidates = c.keys[""]
		} else {
			return nil, fmt.Errorf("%w: unknown kid %q", ErrJWKS, kid)
		}
	}
	return pickCandidate(candidates, kid, alg)
}

// pickCandidate walks candidates and returns the first one whose declared
// alg/use/key_ops match the token's alg. kid is carried only so the error
// message names the right value; the matching itself depends on alg.
func pickCandidate(candidates []candidate, kid, alg string) (crypto.PublicKey, error) {
	for _, cand := range candidates {
		if !cand.matches(alg) {
			continue
		}
		return cand.pub, nil
	}
	if kid == "" {
		return nil, fmt.Errorf("%w: no candidate matches alg %q", ErrJWKS, alg)
	}
	return nil, fmt.Errorf("%w: no candidate for kid %q matches alg %q", ErrJWKS, kid, alg)
}

// matches reports whether the candidate may verify a token signed with alg,
// applying the JWK's declared alg/use/key_ops restrictions. A key published
// with alg:"RS256" cannot verify PS256 (RFC 8725 §3.1); a key with
// key_ops:["encrypt"] cannot verify signatures at all (RFC 7517 §4.3).
func (cand candidate) matches(alg string) bool {
	if cand.alg != "" && cand.alg != alg {
		return false
	}
	if cand.use != "" && cand.use != "sig" {
		return false
	}
	if len(cand.keyOps) > 0 {
		if _, ok := cand.keyOps["verify"]; !ok {
			return false
		}
	}
	return true
}

// refresh fetches the JWKS and replaces the cached key set. An HTTP 200 with
// zero usable keys is treated as an authoritative empty set: the cache is
// replaced with it, so lookups fail closed rather than matching an old key.
func (c *jwksCache) refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return fmt.Errorf("%w: build request: %w", ErrJWKS, err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		// Do not treat a cancellation of the caller's context as a refresh
		// failure. Return the context error without recording lastAttempt, so
		// the next caller with a live context can try again immediately
		// instead of being blocked by a minute-long cooldown.
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		c.recordAttempt()
		return fmt.Errorf("%w: %w", ErrJWKS, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, jwksMaxBytes))
	if err != nil {
		c.recordAttempt()
		return fmt.Errorf("%w: read: %w", ErrJWKS, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		c.recordAttempt()
		return fmt.Errorf("%w: status %d", ErrJWKS, resp.StatusCode)
	}

	var doc jwksDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		c.recordAttempt()
		return fmt.Errorf("%w: decode: %w", ErrJWKS, err)
	}

	keys := make(map[string][]candidate, len(doc.Keys))
	var anon []candidate
	for _, k := range doc.Keys {
		// Only signature keys are eligible. A key explicitly published for
		// encryption must never be selected to verify a token signature.
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		pub, err := parseJWK(k)
		if err != nil {
			continue // skip keys we cannot use (unsupported type/curve); others remain usable
		}
		cand := candidate{pub: pub, alg: k.Alg, use: k.Use}
		if len(k.KeyOps) > 0 {
			cand.keyOps = make(map[string]struct{}, len(k.KeyOps))
			for _, op := range k.KeyOps {
				cand.keyOps[op] = struct{}{}
			}
		}
		if k.Kid != "" {
			keys[k.Kid] = append(keys[k.Kid], cand)
		} else {
			anon = append(anon, cand)
		}
	}

	// Treat an empty key set as authoritative. The provider publishes that the
	// keys are gone: replace the cache with the empty set rather than serving
	// the previous entry, so lookups fail closed.
	anonAvailable := len(anon) == 1 && len(keys) == 0
	if anonAvailable {
		keys[""] = anon
	}
	c.mu.Lock()
	c.keys = keys
	c.anonAvailable = anonAvailable
	c.expiresAt = c.now().Add(jwksTTL)
	c.lastAttempt = c.now()
	c.mu.Unlock()
	return nil
}

// recordAttempt stamps lastAttempt to the current clock so subsequent
// unknown-kid lookups throttle themselves instead of forcing another fetch
// during the cooldown.
func (c *jwksCache) recordAttempt() {
	c.mu.Lock()
	c.lastAttempt = c.now()
	c.mu.Unlock()
}

// parseJWK converts a JWK into an RSA or EC public key.
func parseJWK(k jwk) (crypto.PublicKey, error) {
	switch k.Kty {
	case "RSA":
		n, err := b64BigInt(k.N)
		if err != nil {
			return nil, err
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, err
		}
		e := new(big.Int).SetBytes(eBytes)
		// Bound the exponent to 31 bits: it must fit an int on a 32-bit build
		// (int(e.Int64()) would otherwise silently truncate), and a real RSA
		// exponent is tiny (commonly 65537).
		if !e.IsInt64() || e.Int64() < 2 || e.BitLen() > 31 {
			return nil, fmt.Errorf("invalid RSA exponent")
		}
		// Bound the modulus: reject undersized (potentially factorable) keys, and
		// cap the upper end so a hostile JWKS cannot publish a multi-megabit
		// modulus that turns every verification into a heavy modexp (CPU DoS).
		if bits := n.BitLen(); bits < 2048 || bits > 16384 {
			return nil, fmt.Errorf("RSA modulus out of range: %d bits", bits)
		}
		return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
	case "EC":
		curve, err := ecCurve(k.Crv)
		if err != nil {
			return nil, err
		}
		x, err := b64BigInt(k.X)
		if err != nil {
			return nil, err
		}
		y, err := b64BigInt(k.Y)
		if err != nil {
			return nil, err
		}
		// Validate the point lies on the curve via crypto/ecdh, which performs
		// the on-curve check with the modern (non-deprecated) API. The key is
		// then used for ECDSA signature verification.
		if err := ecPointOnCurve(k.Crv, x, y); err != nil {
			return nil, err
		}
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
	default:
		return nil, fmt.Errorf("unsupported key type %q", k.Kty)
	}
}

// ecPointOnCurve validates that (x, y) is a valid point on the named curve,
// using crypto/ecdh's NewPublicKey (which rejects off-curve points) instead of
// the deprecated elliptic.Curve.IsOnCurve.
func ecPointOnCurve(crv string, x, y *big.Int) error {
	var ec ecdh.Curve
	var size int
	switch crv {
	case "P-256":
		ec, size = ecdh.P256(), 32
	case "P-384":
		ec, size = ecdh.P384(), 48
	case "P-521":
		ec, size = ecdh.P521(), 66
	default:
		return fmt.Errorf("unsupported curve %q", crv)
	}
	// FillBytes panics if a value does not fit, so bound the coordinates to the
	// field size first (a malformed JWKS could carry oversized integers).
	if x.Sign() < 0 || y.Sign() < 0 || len(x.Bytes()) > size || len(y.Bytes()) > size {
		return fmt.Errorf("EC coordinate out of range")
	}
	buf := make([]byte, 1+2*size)
	buf[0] = 4 // uncompressed point
	x.FillBytes(buf[1 : 1+size])
	y.FillBytes(buf[1+size:])
	if _, err := ec.NewPublicKey(buf); err != nil {
		return fmt.Errorf("EC point is not on curve: %w", err)
	}
	return nil
}

func ecCurve(crv string) (elliptic.Curve, error) {
	switch crv {
	case "P-256":
		return elliptic.P256(), nil
	case "P-384":
		return elliptic.P384(), nil
	case "P-521":
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("unsupported curve %q", crv)
	}
}

// b64BigInt decodes a base64url (no padding) big-endian unsigned integer.
func b64BigInt(s string) (*big.Int, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(b), nil
}
