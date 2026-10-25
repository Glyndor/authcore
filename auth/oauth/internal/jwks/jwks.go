// Package jwks fetches, caches and selects a provider's JWKS signing keys, enforcing the per-key
// alg/use/key_ops restrictions, a TTL and a refresh cooldown.
package jwks

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/Glyndor/authcore/auth/oauth/internal/jwks/jwk"
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

type jwksDoc struct {
	Keys []jwk.JWK `json:"keys"`
}

// Candidate is a parsed JWK paired with the metadata needed to enforce the
// per-key alg/use/key_ops restrictions at selection time. Two candidates may
// share a kid (RFC 7517 permits an RSA key and an EC key under one kid) and
// the verifier picks by token alg.
type Candidate struct {
	// Pub is the parsed public key.
	Pub    crypto.PublicKey
	alg    string
	use    string
	keyOps map[string]struct{}
	// Issuer is the JWK "issuer" member, "" when the key carries none.
	Issuer string
}

// Cache fetches and caches a provider's signing keys. Per kid, the cache
// holds a slice of candidates so two providers sharing a kid (e.g. an RSA and
// an EC key) remain individually selectable; selection is driven by the
// token's kid and alg headers.
type Cache struct {
	url  string
	http *http.Client
	errs Errors

	group singleflight.Group // collapses concurrent refreshes into one outbound fetch

	mu            sync.RWMutex
	keys          map[string][]Candidate // kid -> candidates
	anonAvailable bool                   // true when the set has exactly one key with no kid
	expiresAt     time.Time
	lastAttempt   time.Time // last refresh attempt, to throttle unknown-kid-driven fetches

	// now returns the current time. Overridden in tests so the TTL can be
	// advanced without sleeping. Defaults to time.Now.
	now func() time.Time
}

// Errors carries the sentinel errors the cache wraps its failures with. They
// are owned by the public oauth package (ErrJWKS and ErrJWKSStale), which
// passes them in so errors.Is keeps working across the package boundary.
type Errors struct {
	// Fetch wraps every failure to obtain or select a signing key.
	Fetch error
	// Stale wraps a refresh failure once the cached key set has expired.
	Stale error
}

// New returns a cache that fetches the key set at url with h and wraps its
// failures with errs.
func New(url string, h *http.Client, errs Errors) *Cache {
	return &Cache{
		url:  url,
		http: h,
		errs: errs,
		keys: make(map[string][]Candidate),
		now:  time.Now,
	}
}

// Key returns the public key for verifying a token whose header carries the
// given kid and alg. When kid is empty and the cached set has exactly one key
// with no kid, that key is returned (OIDC permits a JWKS of one key without
// a kid). The per-key alg/use/key_ops restrictions declared on the JWK are
// enforced here, so a key published with alg:"RS256" cannot verify a PS256
// token and a key published with key_ops:["encrypt"] cannot verify at all.
//
// It refreshes the cache when the entry is missing or stale, since refreshing
// on an unknown kid is how key rotation is picked up. If a refresh fails but
// the cached key set for kid is still inside its TTL, that set is used; once
// the TTL has passed, a failed refresh fails closed with the Stale error so a
// withdrawn key cannot outlive the outage.
func (c *Cache) Key(ctx context.Context, kid, alg string) (crypto.PublicKey, error) {
	cand, err := c.CandidateFor(ctx, kid, alg)
	if err != nil {
		return nil, err
	}
	return cand.Pub, nil
}

// CandidateFor is Key, returning the whole selected Candidate so the caller
// can enforce restrictions that depend on the token's claims (the JWK
// "issuer" member) after the signature has been checked.
func (c *Cache) CandidateFor(ctx context.Context, kid, alg string) (Candidate, error) {
	c.mu.RLock()
	candidates, ok := c.keys[kid]
	expires := c.expiresAt
	lastAttempt := c.lastAttempt
	c.mu.RUnlock()

	now := c.now()
	if ok && now.Before(expires) {
		return pickCandidate(c.errs.Fetch, candidates, kid, alg)
	}

	// Skip an unknown kid only while a recent failed refresh is still inside
	// the cooldown. While another caller's refresh is in flight, lastAttempt
	// carries the previous attempt's timestamp, so concurrent callers join it
	// rather than being refused up front.
	if !ok && now.Sub(lastAttempt) < minRefreshInterval {
		return Candidate{}, fmt.Errorf("%w: unknown kid %q", c.errs.Fetch, kid)
	}
	// A known kid whose set has expired gets the same cooldown. A successful
	// refresh moves the expiry an hour ahead, so an attempt inside the window
	// here was a failed one. Before 2026-09-25 every verification during an
	// outage made its own fetch toward the failing provider.
	if ok && now.Sub(lastAttempt) < minRefreshInterval {
		return Candidate{}, fmt.Errorf("%w: %w: the last refresh failed less than %s ago", c.errs.Stale, c.errs.Fetch, minRefreshInterval)
	}

	// Collapse concurrent refreshes: a burst of tokens carrying distinct
	// unknown kids must produce a single outbound JWKS fetch, not one per
	// request.
	_, err, _ := c.group.Do(c.url, func() (any, error) { return nil, c.refresh(ctx) })
	if err != nil && errors.Is(err, context.Canceled) && ctx.Err() == nil {
		// The shared fetch runs under the context of the caller that started
		// it. When that caller went away, every caller that joined got its
		// cancellation. This caller's context is live, so fetch again.
		_, err, _ = c.group.Do(c.url, func() (any, error) { return nil, c.refresh(ctx) })
	}
	if err != nil {
		if ok {
			if now.Before(expires) {
				return pickCandidate(c.errs.Fetch, candidates, kid, alg) // known set inside its TTL: serve it on a transient JWKS outage
			}
			// Past expiry: fail closed. A withdrawn key must not remain usable
			// while the provider is unreachable.
			return Candidate{}, fmt.Errorf("%w: %w", c.errs.Stale, err)
		}
		return Candidate{}, err
	}

	c.mu.RLock()
	candidates, ok = c.keys[kid]
	anonAvailable := c.anonAvailable
	c.mu.RUnlock()
	if !ok {
		if kid == "" && anonAvailable {
			candidates = c.keys[""]
		} else {
			return Candidate{}, fmt.Errorf("%w: unknown kid %q", c.errs.Fetch, kid)
		}
	}
	return pickCandidate(c.errs.Fetch, candidates, kid, alg)
}

// pickCandidate walks candidates and returns the first one whose declared
// alg/use/key_ops match the token's alg. kid is carried only so the error
// message names the right value; the matching itself depends on alg.
func pickCandidate(errFetch error, candidates []Candidate, kid, alg string) (Candidate, error) {
	for _, cand := range candidates {
		if !cand.matches(alg) {
			continue
		}
		return cand, nil
	}
	if kid == "" {
		return Candidate{}, fmt.Errorf("%w: no candidate matches alg %q", errFetch, alg)
	}
	return Candidate{}, fmt.Errorf("%w: no candidate for kid %q matches alg %q", errFetch, kid, alg)
}

// matches reports whether the Candidate may verify a token signed with alg,
// applying the JWK's declared alg/use/key_ops restrictions. A key published
// with alg:"RS256" cannot verify PS256 (RFC 8725 §3.1); a key with
// key_ops:["encrypt"] cannot verify signatures at all (RFC 7517 §4.3).
func (cand Candidate) matches(alg string) bool {
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
func (c *Cache) refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return fmt.Errorf("%w: build request: %w", c.errs.Fetch, err)
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
		return fmt.Errorf("%w: %w", c.errs.Fetch, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, jwksMaxBytes))
	if err != nil {
		c.recordAttempt()
		return fmt.Errorf("%w: read: %w", c.errs.Fetch, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		c.recordAttempt()
		return fmt.Errorf("%w: status %d", c.errs.Fetch, resp.StatusCode)
	}

	var doc jwksDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		c.recordAttempt()
		return fmt.Errorf("%w: decode: %w", c.errs.Fetch, err)
	}

	keys := make(map[string][]Candidate, len(doc.Keys))
	var anon []Candidate
	for _, k := range doc.Keys {
		// Only signature keys are eligible. A key explicitly published for
		// encryption must never be selected to verify a token signature.
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		pub, err := jwk.Parse(k)
		if err != nil {
			continue // skip keys we cannot use (unsupported type/curve); others remain usable
		}
		cand := Candidate{Pub: pub, alg: k.Alg, use: k.Use, Issuer: k.Issuer}
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
func (c *Cache) recordAttempt() {
	c.mu.Lock()
	c.lastAttempt = c.now()
	c.mu.Unlock()
}
