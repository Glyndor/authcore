// Package mx verifies that an email domain can receive mail through a DNS MX
// lookup, with a per-domain result cache and de-duplication of concurrent
// lookups.
package mx

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/Glyndor/authcore/auth/email/internal/errs"
)

// mxLookupTimeout bounds one shared MX lookup. It is the module's own bound,
// independent of any caller's deadline: a caller whose deadline passes stops
// waiting, and the lookup finishes for the others.
const mxLookupTimeout = 10 * time.Second

// Resolver is the slice of net.Resolver that Verify depends on. A
// narrow interface keeps the production code against the stdlib type and
// lets tests swap in a deterministic stub without spinning up a fake DNS
// server.
type Resolver interface {
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
}

// Verifier performs cached, single-flight MX lookups. It is safe for
// concurrent use and owns no background goroutine.
type Verifier struct {
	resolver Resolver
	cacheTTL time.Duration
	cache    *cache
	group    singleflight.Group
}

// New creates a Verifier that resolves through resolver and keeps confirmed
// results for cacheTTL.
func New(resolver Resolver, cacheTTL time.Duration) *Verifier {
	return &Verifier{resolver: resolver, cacheTTL: cacheTTL, cache: newCache()}
}

// Verify performs a DNS MX lookup on the domain of address.
//
// It returns nil when the domain accepts mail, errs.ErrDomainNoMX when it has
// no MX (or an address without a domain), errs.ErrDomainUnresolvable when the
// lookup failed, and errs.ErrInvalidEmail when the domain exceeds DNS size
// limits so it was not looked up.
//
// ctx bounds how long this caller waits. Concurrent callers for the same
// domain share a single DNS query through singleflight; the query itself runs
// under the module's own 10-second bound rather than any one caller's
// context, so a caller that gives up or disconnects neither blocks the others
// nor decides their answer.
func (v *Verifier) Verify(ctx context.Context, address string) error {
	domain := domainOf(address)
	if domain == "" {
		return errs.ErrDomainNoMX
	}
	if !plausibleDomain(domain) {
		return fmt.Errorf("%w: domain exceeds DNS size limits", errs.ErrInvalidEmail)
	}

	// Fast path: valid cache hit.
	if entry, ok := v.cache.cached(domain); ok {
		return entryErr(entry)
	}

	// Slow path: deduplicated DNS lookup.
	// singleflight.Group ensures that N concurrent callers for the same domain
	// fire exactly one DNS query; all share the result. This prevents thundering
	// herd when a cache entry expires under high concurrency.
	//
	// Each caller selects on its own ctx.Done() so a short deadline on a
	// late-arriving caller does not block on the first caller's lookup.
	// DoChan returns a channel that closes exactly once with the shared
	// result; an early return on ctx.Done() abandons the channel for this
	// caller only, and the in-flight lookup completes for the others. The cache is populated inside the function
	// so a deadline-limited caller benefits from another caller's answer.
	ch := v.group.DoChan(domain, func() (any, error) { return v.lookup(ctx, domain) })
	select {
	case <-ctx.Done():
		return ctx.Err()
	case r := <-ch:
		if r.Err != nil {
			return r.Err
		}
		return entryErr(r.Val.(cacheEntry))
	}
}

// lookup runs the shared MX query for domain and records the outcome in the
// cache.
func (v *Verifier) lookup(ctx context.Context, domain string) (any, error) {
	// The shared lookup must not run on one caller's context: when that
	// request was abandoned, the lookup failed, was cached as
	// "unresolvable" for 30 s, and every caller got the soft answer the
	// docs say never to block on, even for a domain with no MX
	// (measured 2026-09-25). It keeps the caller's values and runs under
	// the module's own bound.
	lookupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), mxLookupTimeout)
	defer cancel()
	mxs, err := v.resolver.LookupMX(lookupCtx, domain)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			// Authoritative "no such host" or "no records of this type"
			// (NXDOMAIN or NODATA for MX): the resolver answered with a
			// final answer, not a transport error. Classify this as a
			// definitive no-MX result and cache it with the normal TTL
			// so subsequent calls do not retry the lookup.
			entry := cacheEntry{hasMX: false, expiresAt: time.Now().Add(v.cacheTTL)}
			v.cache.store(domain, entry)
			return nil, errs.NoMX(err)
		}
		v.cache.store(domain, cacheEntry{dnsFailure: true, expiresAt: time.Now().Add(30 * time.Second)})
		return nil, errs.Unresolvable(err)
	}
	entry := cacheEntry{hasMX: hasRealMX(mxs), expiresAt: time.Now().Add(v.cacheTTL)}
	v.cache.store(domain, entry)
	return entry, nil
}
