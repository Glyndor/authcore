// Package jwks fetches, caches and selects a provider's JWKS signing keys, enforcing the per-key
// alg/use/key_ops restrictions, a TTL and a refresh cooldown.
package jwks

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/Glyndor/authcore/auth/oauth/internal/jwks/candidate"
	"github.com/Glyndor/authcore/auth/oauth/internal/jwks/fetch"
	"github.com/Glyndor/authcore/auth/oauth/internal/safetext"
)

const (
	// jwksTTL bounds how long a fetched key set is trusted before a refresh.
	jwksTTL = time.Hour
	// minRefreshInterval throttles refreshes triggered by an unknown kid. Without
	// it, a flood of tokens carrying bogus kids would force one outbound JWKS GET
	// per verification (request amplification). A genuine key rotation is still
	// picked up within this window.
	minRefreshInterval = time.Minute
)

// Candidate is a parsed JWK paired with the metadata needed to enforce the
// per-key restrictions at selection time. See package candidate.
type Candidate = candidate.Candidate

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
		return candidate.Pick(c.errs.Fetch, candidates, kid, alg)
	}

	// Skip an unknown kid only while a recent failed refresh is still inside
	// the cooldown. While another caller's refresh is in flight, lastAttempt
	// carries the previous attempt's timestamp, so concurrent callers join it
	// rather than being refused up front.
	if !ok && now.Sub(lastAttempt) < minRefreshInterval {
		return Candidate{}, fmt.Errorf("%w: unknown kid %s", c.errs.Fetch, safetext.Quote(kid))
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
				return candidate.Pick(c.errs.Fetch, candidates, kid, alg) // known set inside its TTL: serve it on a transient JWKS outage
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
			return Candidate{}, fmt.Errorf("%w: unknown kid %s", c.errs.Fetch, safetext.Quote(kid))
		}
	}
	return candidate.Pick(c.errs.Fetch, candidates, kid, alg)
}

// refresh fetches the JWKS and replaces the cached key set. An HTTP 200 with
// zero usable keys is treated as an authoritative empty set: the cache is
// replaced with it, so lookups fail closed rather than matching an old key.
func (c *Cache) refresh(ctx context.Context) error {
	set, err := fetch.Get(ctx, c.http, c.url, c.errs.Fetch, c.recordAttempt)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.keys = set.Keys
	c.anonAvailable = set.AnonAvailable
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
