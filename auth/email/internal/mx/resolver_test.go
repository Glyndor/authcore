package mx

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/email/internal/errs"
)

// TestVerifyDomain_rejectsNullMX covers RFC 7505 section 3: a domain that
// publishes a single MX record with host "." (the "null MX") is declaring
// that it accepts no mail. The module must return errs.ErrDomainNoMX, not nil,
// and cache the result so subsequent calls do not re-query DNS.
func TestVerifyDomain_rejectsNullMX(t *testing.T) {
	m := newVerifier()
	m.resolver = newStub([]*net.MX{{Host: ".", Pref: 0}}, nil)

	err := m.Verify(context.Background(), "user@null.example")
	if !errors.Is(err, errs.ErrDomainNoMX) {
		t.Errorf("null MX must return errs.ErrDomainNoMX, got %v", err)
	}

	// The result must be cached: a second call does not re-query DNS.
	err = m.Verify(context.Background(), "user@null.example")
	if !errors.Is(err, errs.ErrDomainNoMX) {
		t.Errorf("cached null-MX lookup must return errs.ErrDomainNoMX, got %v", err)
	}
}

// Acceptance pair for TestVerifyDomain_rejectsNullMX: a single, non-null MX
// record is a real MX and verifies cleanly. Without this pair the rejection
// above would pass for any single-record answer.
func TestVerifyDomain_acceptsSingleRealMX(t *testing.T) {
	m := newVerifier()
	m.resolver = newStub([]*net.MX{{Host: "mail.example.com.", Pref: 10}}, nil)

	if err := m.Verify(context.Background(), "user@example.com"); err != nil {
		t.Errorf("real MX must verify, got %v", err)
	}
}

// TestVerifyDomain_notFoundIsNoMX: when the resolver answers authoritatively
// that no MX records exist for the domain (NXDOMAIN or NODATA, surfaced by
// Go's resolver as *net.DNSError with IsNotFound set), the module must
// classify this as errs.ErrDomainNoMX (the domain does not accept mail) and
// cache it so the second call returns the same error without re-querying
// DNS.
func TestVerifyDomain_notFoundIsNoMX(t *testing.T) {
	stub := newStub(nil, &net.DNSError{IsNotFound: true})
	m := newVerifier()
	m.resolver = stub

	err := m.Verify(context.Background(), "user@absent.example")
	if !errors.Is(err, errs.ErrDomainNoMX) {
		t.Errorf("IsNotFound must be classified as errs.ErrDomainNoMX, got %v", err)
	}

	// Second call must hit the cache, not the resolver.
	err = m.Verify(context.Background(), "user@absent.example")
	if !errors.Is(err, errs.ErrDomainNoMX) {
		t.Errorf("cached not-found must return errs.ErrDomainNoMX, got %v", err)
	}
	if got := stub.calls(); got != 1 {
		t.Errorf("resolver must be called once across two lookups, got %d", got)
	}
}

// TestVerifyDomain_timeoutStaysSoft: a lookup failure with no NXDOMAIN/NODATA
// signal (a timeout, SERVFAIL, a transport error) is not authoritative "no
// mail". It stays in the soft-failure bucket (errs.ErrDomainUnresolvable) so the
// caller does not block the user. The not-found classification above must
// not bleed into this case.
func TestVerifyDomain_timeoutStaysSoft(t *testing.T) {
	stub := newStub(nil, &net.DNSError{IsTimeout: true})
	m := newVerifier()
	m.resolver = stub

	err := m.Verify(context.Background(), "user@slow.example")
	if !errors.Is(err, errs.ErrDomainUnresolvable) {
		t.Errorf("IsTimeout must be classified as errs.ErrDomainUnresolvable, got %v", err)
	}
	if errors.Is(err, errs.ErrDomainNoMX) {
		t.Error("IsTimeout must NOT be classified as errs.ErrDomainNoMX")
	}
}

// An MX answer with no records and no error is a domain without MX, not one
// that accepts mail. The branch could be deleted with the suite green.
func TestVerifyDomain_emptyAnswerIsNoMX(t *testing.T) {
	m := newVerifier()
	stub := newStub([]*net.MX{}, nil)
	m.resolver = stub
	if err := m.Verify(context.Background(), "user@nomx.example"); !errors.Is(err, errs.ErrDomainNoMX) {
		t.Fatalf("empty answer: %v, want errs.ErrDomainNoMX", err)
	}
	m.resolver = newStub([]*net.MX{{Host: "mx.example.", Pref: 10}}, nil)
	if err := m.Verify(context.Background(), "user@hasmx.example"); err != nil {
		t.Fatalf("a real record: %v, want nil", err)
	}
}

func TestVerifyDomain_dnsFailureReturnsErrDomainUnresolvable(t *testing.T) {
	m := newVerifier()
	m.resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, errors.New("no network")
		},
	}
	err := m.Verify(context.Background(), "user@unreachable.example")
	if !errors.Is(err, errs.ErrDomainUnresolvable) {
		t.Errorf("expected errs.ErrDomainUnresolvable, got %v", err)
	}
}

func TestVerifyDomain_dnsFailureIsWrapped(t *testing.T) {
	m := newVerifier()
	m.resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, errors.New("no network")
		},
	}
	err := m.Verify(context.Background(), "user@unreachable.example")
	if errors.Unwrap(err) == nil {
		t.Error("errs.ErrDomainUnresolvable must wrap the underlying DNS error")
	}
}

// TestVerifyDomain_dnsFailureIsServedFromCache pins the dnsFailure flag
// on the cached entry: a DNS failure has to be cached as dnsFailure=true
// so the second call returns errs.ErrDomainUnresolvable (soft failure) rather
// than errs.ErrDomainNoMX (hard failure, which would block the user on a
// transient transport error).
//
// The test counts the resolver dial attempts: the first call must hit
// DNS at least once, and the second must hit it zero additional times
// (a cache hit). The exact count on the first call is left to the Go
// resolver's retry policy. What matters for the assertion is that the
// second call does not increase it. Together, the no-increment-on-second-
// call and the error code are what catch the "remove dnsFailure: true
// from the cache write" sabotage. A cache that stores the failure with
// dnsFailure=false and hasMX=false still returns errs.ErrDomainNoMX on the
// second call, and the test sees the wrong error type instead of the
// soft one.
func TestVerifyDomain_dnsFailureIsServedFromCache(t *testing.T) {
	m := newVerifier()
	var calls int32
	m.resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			atomic.AddInt32(&calls, 1)
			return nil, errors.New("no network")
		},
	}

	// First call: must hit DNS at least once and must return
	// errs.ErrDomainUnresolvable; the failure must be cached under
	// dnsFailure=true.
	first := m.Verify(context.Background(), "user@flaky.example")
	if !errors.Is(first, errs.ErrDomainUnresolvable) {
		t.Fatalf("first VerifyDomain: got %v, want errs.ErrDomainUnresolvable", first)
	}
	firstCalls := atomic.LoadInt32(&calls)
	if firstCalls < 1 {
		t.Fatalf("first VerifyDomain: no DNS dial attempted, got %d", firstCalls)
	}

	// Second call: must NOT hit DNS again (cache hit) and must still
	// return errs.ErrDomainUnresolvable (not errs.ErrDomainNoMX).
	second := m.Verify(context.Background(), "user@flaky.example")
	if !errors.Is(second, errs.ErrDomainUnresolvable) {
		t.Errorf("second VerifyDomain: got %v, want errs.ErrDomainUnresolvable", second)
	}
	if errors.Is(second, errs.ErrDomainNoMX) {
		t.Error("second VerifyDomain: got errs.ErrDomainNoMX; cached DNS failure must not be served as errs.ErrDomainNoMX")
	}
	if got := atomic.LoadInt32(&calls); got != firstCalls {
		t.Errorf("second VerifyDomain: dial count went from %d to %d; cache must be hit, not DNS", firstCalls, got)
	}
}

func TestVerifyDomain_expiredCacheHitsDNS(t *testing.T) {
	m := newVerifier()
	// Write an expired positive entry — it must NOT be used.
	m.cache.mu.Lock()
	m.cache.entries["example.com"] = cacheEntry{hasMX: true, expiresAt: time.Now().Add(-time.Second)}
	m.cache.mu.Unlock()

	// DNS will fail (no real network in unit tests using a broken resolver).
	m.resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, errors.New("no network")
		},
	}
	err := m.Verify(context.Background(), "user@example.com")
	if !errors.Is(err, errs.ErrDomainUnresolvable) {
		t.Errorf("expected errs.ErrDomainUnresolvable after cache miss + DNS failure, got %v", err)
	}
}
