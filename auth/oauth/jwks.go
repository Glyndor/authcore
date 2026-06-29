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
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"
)

const (
	// jwksTTL bounds how long a fetched key set is trusted before a refresh.
	jwksTTL = time.Hour
	// jwksMaxBytes caps a JWKS response so a hostile endpoint cannot exhaust memory.
	jwksMaxBytes = 1 << 20
)

// jwk is one JSON Web Key. Only the fields needed to build an RSA or EC public
// key are decoded.
type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	N   string `json:"n"` // RSA modulus (base64url)
	E   string `json:"e"` // RSA exponent (base64url)
	Crv string `json:"crv"`
	X   string `json:"x"` // EC x (base64url)
	Y   string `json:"y"` // EC y (base64url)
}

type jwksDoc struct {
	Keys []jwk `json:"keys"`
}

// jwksCache fetches and caches a provider's signing keys, indexed by kid.
type jwksCache struct {
	url  string
	http *http.Client

	mu        sync.RWMutex
	keys      map[string]crypto.PublicKey
	expiresAt time.Time
}

func newJWKSCache(url string, h *http.Client) *jwksCache {
	return &jwksCache{url: url, http: h, keys: make(map[string]crypto.PublicKey)}
}

// key returns the public key for kid. It refreshes the cache when the entry is
// missing or stale — refreshing on an unknown kid is how key rotation is picked
// up. If a refresh fails but a cached key for kid still exists, that key is used.
func (c *jwksCache) key(ctx context.Context, kid string) (crypto.PublicKey, error) {
	c.mu.RLock()
	k, ok := c.keys[kid]
	fresh := time.Now().Before(c.expiresAt)
	c.mu.RUnlock()
	if ok && fresh {
		return k, nil
	}

	if err := c.refresh(ctx); err != nil {
		if ok {
			return k, nil // serve the stale key rather than fail the login on a transient JWKS outage
		}
		return nil, err
	}

	c.mu.RLock()
	k, ok = c.keys[kid]
	c.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%w: unknown kid %q", ErrJWKS, kid)
	}
	return k, nil
}

// refresh fetches the JWKS and replaces the cached key set.
func (c *jwksCache) refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return fmt.Errorf("%w: build request: %w", ErrJWKS, err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrJWKS, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, jwksMaxBytes))
	if err != nil {
		return fmt.Errorf("%w: read: %w", ErrJWKS, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%w: status %d", ErrJWKS, resp.StatusCode)
	}

	var doc jwksDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return fmt.Errorf("%w: decode: %w", ErrJWKS, err)
	}

	keys := make(map[string]crypto.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		pub, err := parseJWK(k)
		if err != nil {
			continue // skip keys we cannot use (unsupported type/curve); others remain usable
		}
		if k.Kid != "" {
			keys[k.Kid] = pub
		}
	}
	if len(keys) == 0 {
		return fmt.Errorf("%w: no usable keys in JWKS", ErrJWKS)
	}

	c.mu.Lock()
	c.keys = keys
	c.expiresAt = time.Now().Add(jwksTTL)
	c.mu.Unlock()
	return nil
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
		if !e.IsInt64() || e.Int64() < 2 {
			return nil, fmt.Errorf("invalid RSA exponent")
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
