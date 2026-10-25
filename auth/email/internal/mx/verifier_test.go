package mx

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/email/internal/errs"
)

func TestVerifyDomain_noAtSignReturnsErrDomainNoMX(t *testing.T) {
	m := newVerifier()
	err := m.Verify(context.Background(), "notanemail")
	if !errors.Is(err, errs.ErrDomainNoMX) {
		t.Errorf("expected errs.ErrDomainNoMX for address with no '@', got %v", err)
	}
}

func TestVerifyDomain_cachedPositiveReturnsNil(t *testing.T) {
	m := newVerifier()
	primeCache(m, "example.com", true, time.Minute)

	if err := m.Verify(context.Background(), "user@example.com"); err != nil {
		t.Errorf("expected nil, got %v", err)
	}
}

func TestVerifyDomain_cachedNegativeReturnsErrDomainNoMX(t *testing.T) {
	m := newVerifier()
	primeCache(m, "nodomain.example", false, time.Minute)

	err := m.Verify(context.Background(), "user@nodomain.example")
	if !errors.Is(err, errs.ErrDomainNoMX) {
		t.Errorf("expected errs.ErrDomainNoMX, got %v", err)
	}
}

func TestVerifyDomain_cachedDnsFailureReturnsErrDomainUnresolvable(t *testing.T) {
	// Regression: a DNS failure cached as hasMX=false must NOT return
	// errs.ErrDomainNoMX on subsequent cache hits — that would incorrectly block
	// the user. It must return errs.ErrDomainUnresolvable (soft failure).
	m := newVerifier()
	m.cache.mu.Lock()
	m.cache.entries["unreachable.example"] = cacheEntry{
		dnsFailure: true,
		expiresAt:  time.Now().Add(time.Minute),
	}
	m.cache.mu.Unlock()

	err := m.Verify(context.Background(), "user@unreachable.example")
	if !errors.Is(err, errs.ErrDomainUnresolvable) {
		t.Errorf("cached DNS failure must return errs.ErrDomainUnresolvable, got %v", err)
	}
	if errors.Is(err, errs.ErrDomainNoMX) {
		t.Error("cached DNS failure must NOT return errs.ErrDomainNoMX")
	}
}

// VerifyDomain refuses a value no DNS name can have before the cache or the
// resolver sees it, so unvalidated input cannot pin memory in the cache.
func TestVerifyDomain_refusesAnImplausibleDomainWithoutLookingItUp(t *testing.T) {
	m := newVerifier()
	stub := newStub(nil, &net.DNSError{IsNotFound: true})
	m.resolver = stub
	for _, domain := range []string{strings.Repeat("a", 250) + ".com", strings.Repeat("b", 64) + ".example"} {
		err := m.Verify(context.Background(), "user@"+domain)
		if !errors.Is(err, errs.ErrInvalidEmail) {
			t.Errorf("%d-byte domain: %v, want errs.ErrInvalidEmail", len(domain), err)
		}
	}
	if stub.calls() != 0 {
		t.Fatalf("the resolver was asked %d times, want none", stub.calls())
	}
	m.cache.mu.RLock()
	cached := len(m.cache.entries)
	m.cache.mu.RUnlock()
	if cached != 0 {
		t.Fatalf("%d cache entries, want none", cached)
	}
	if err := m.Verify(context.Background(), "user@"+strings.Repeat("c", 63)+".example"); !errors.Is(err, errs.ErrDomainNoMX) {
		t.Fatalf("a 63-byte label: %v, want the lookup to run and answer no-MX", err)
	}
}
