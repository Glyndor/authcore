package email

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"testing/synctest"

	"github.com/Glyndor/authcore"
)

type nilLoggerProvider struct{ fakeProvider }

func (nilLoggerProvider) Logger() authcore.Logger { return nil }

// A nil provider or logger panicked until 2026-09-25.
func TestNewWithConfig_refusesANilProviderOrLogger(t *testing.T) {
	if _, err := New(nil); !errors.Is(err, ErrInvalidConfig) || !strings.Contains(err.Error(), "provider is nil") {
		t.Errorf("New(nil) = %v, want ErrInvalidConfig", err)
	}
	if _, err := NewWithConfig(nilLoggerProvider{}, Config{}); !errors.Is(err, ErrInvalidConfig) || !strings.Contains(err.Error(), "Logger() returned nil") {
		t.Errorf("nil logger = %v, want ErrInvalidConfig", err)
	}
}

// An all-digit top-level label is a bare IPv4 address in another spelling.
func TestValidateAndNormalize_refusesAnAllDigitTopLevelDomain(t *testing.T) {
	m := newMod(t)
	for _, addr := range []string{"user@127.0.0.1", "user@1.2"} {
		if _, err := m.ValidateAndNormalize(addr); !errors.Is(err, ErrInvalidEmail) || !strings.Contains(err.Error(), "top-level domain must not be all digits") {
			t.Errorf("%s: %v, want the all-digit refusal", addr, err)
		}
	}
	for _, addr := range []string{"user@123.example.com", "user@example.co1"} {
		if _, err := m.ValidateAndNormalize(addr); err != nil {
			t.Errorf("%s: %v, want accepted", addr, err)
		}
	}
}

// VerifyDomain refuses a value no DNS name can have before the cache or the
// resolver sees it, so unvalidated input cannot pin memory in the cache.
func TestVerifyDomain_refusesAnImplausibleDomainWithoutLookingItUp(t *testing.T) {
	m := newMod(t)
	stub := newStub(nil, &net.DNSError{IsNotFound: true})
	m.resolver = stub
	for _, domain := range []string{strings.Repeat("a", 250) + ".com", strings.Repeat("b", 64) + ".example"} {
		err := m.VerifyDomain(context.Background(), "user@"+domain)
		if !errors.Is(err, ErrInvalidEmail) {
			t.Errorf("%d-byte domain: %v, want ErrInvalidEmail", len(domain), err)
		}
	}
	if stub.calls() != 0 {
		t.Fatalf("the resolver was asked %d times, want none", stub.calls())
	}
	m.mu.RLock()
	cached := len(m.cache)
	m.mu.RUnlock()
	if cached != 0 {
		t.Fatalf("%d cache entries, want none", cached)
	}
	if err := m.VerifyDomain(context.Background(), "user@"+strings.Repeat("c", 63)+".example"); !errors.Is(err, ErrDomainNoMX) {
		t.Fatalf("a 63-byte label: %v, want the lookup to run and answer no-MX", err)
	}
}

// When the caller that started a shared lookup goes away, the lookup still
// finishes and the others get its real answer. It ran on that caller's
// context until 2026-09-25, so they got the soft "unresolvable" instead,
// cached for 30 seconds.
func TestVerifyDomain_theStartersCancellationDoesNotDecideForOthers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m := newMod(t)
		stub := withBlockingStub(nil, &net.DNSError{IsNotFound: true})
		m.resolver = stub

		ctxA, cancelA := context.WithCancel(context.Background())
		errA := make(chan error, 1)
		go func() { errA <- m.VerifyDomain(ctxA, "user@gone.example") }()
		<-stub.started

		errB := make(chan error, 1)
		go func() { errB <- m.VerifyDomain(context.Background(), "user@gone.example") }()
		synctest.Wait() // B has joined A's lookup

		cancelA()
		if err := <-errA; !errors.Is(err, context.Canceled) {
			t.Fatalf("the cancelled starter got %v, want context.Canceled", err)
		}
		close(stub.release)
		if err := <-errB; !errors.Is(err, ErrDomainNoMX) {
			t.Fatalf("the joined caller got %v, want ErrDomainNoMX", err)
		}
		if err := m.VerifyDomain(context.Background(), "user@gone.example"); !errors.Is(err, ErrDomainNoMX) {
			t.Fatalf("a later caller got %v, want the cached ErrDomainNoMX", err)
		}
		if n := stub.calls(); n != 1 {
			t.Fatalf("%d lookups, want 1", n)
		}
	})
}
