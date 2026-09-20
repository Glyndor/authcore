package email

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

// stubResolver satisfies mxResolver with deterministic, in-process behaviour.
// The release channel lets a test hold a LookupMX call open until it has
// verified the ordering of concurrent callers; the started channel signals
// when the first call has reached the resolver.
type stubResolver struct {
	mu          sync.Mutex
	callCount   int
	startedOnce sync.Once
	started     chan struct{}
	release     chan struct{}
	mx          []*net.MX
	err         error
}

func (s *stubResolver) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	s.mu.Lock()
	s.callCount++
	s.mu.Unlock()
	s.startedOnce.Do(func() { close(s.started) })
	if s.release != nil {
		select {
		case <-s.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return s.mx, s.err
}

func (s *stubResolver) calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.callCount
}

// newStub returns a stub whose LookupMX returns immediately. Tests that
// need to hold a call open call withBlockingStub instead.
func newStub(mx []*net.MX, err error) *stubResolver {
	return &stubResolver{
		started: make(chan struct{}),
		mx:      mx,
		err:     err,
	}
}

// withBlockingStub returns a stub whose first LookupMX blocks until release
// is closed or the caller's context is cancelled. The started channel is
// closed when the call reaches LookupMX so the test can wait until the
// in-flight lookup is positioned before issuing the second call.
func withBlockingStub(mx []*net.MX, err error) *stubResolver {
	return &stubResolver{
		started: make(chan struct{}),
		release: make(chan struct{}),
		mx:      mx,
		err:     err,
	}
}

// TestVerifyDomain_rejectsNullMX covers RFC 7505 section 3: a domain that
// publishes a single MX record with host "." (the "null MX") is declaring
// that it accepts no mail. The module must return ErrDomainNoMX, not nil,
// and cache the result so subsequent calls do not re-query DNS.
func TestVerifyDomain_rejectsNullMX(t *testing.T) {
	m := newMod(t)
	m.resolver = newStub([]*net.MX{{Host: ".", Pref: 0}}, nil)

	err := m.VerifyDomain(context.Background(), "user@null.example")
	if !errors.Is(err, ErrDomainNoMX) {
		t.Errorf("null MX must return ErrDomainNoMX, got %v", err)
	}

	// The result must be cached: a second call does not re-query DNS.
	err = m.VerifyDomain(context.Background(), "user@null.example")
	if !errors.Is(err, ErrDomainNoMX) {
		t.Errorf("cached null-MX lookup must return ErrDomainNoMX, got %v", err)
	}
}

// Acceptance pair for TestVerifyDomain_rejectsNullMX: a single, non-null MX
// record is a real MX and verifies cleanly. Without this pair the rejection
// above would pass for any single-record answer.
func TestVerifyDomain_acceptsSingleRealMX(t *testing.T) {
	m := newMod(t)
	m.resolver = newStub([]*net.MX{{Host: "mail.example.com.", Pref: 10}}, nil)

	if err := m.VerifyDomain(context.Background(), "user@example.com"); err != nil {
		t.Errorf("real MX must verify, got %v", err)
	}
}

// TestVerifyDomain_notFoundIsNoMX: when the resolver answers authoritatively
// that no MX records exist for the domain (NXDOMAIN or NODATA, surfaced by
// Go's resolver as *net.DNSError with IsNotFound set), the module must
// classify this as ErrDomainNoMX — the domain does not accept mail — and
// cache it so the second call returns the same error without re-querying
// DNS.
func TestVerifyDomain_notFoundIsNoMX(t *testing.T) {
	stub := newStub(nil, &net.DNSError{IsNotFound: true})
	m := newMod(t)
	m.resolver = stub

	err := m.VerifyDomain(context.Background(), "user@absent.example")
	if !errors.Is(err, ErrDomainNoMX) {
		t.Errorf("IsNotFound must be classified as ErrDomainNoMX, got %v", err)
	}

	// Second call must hit the cache, not the resolver.
	err = m.VerifyDomain(context.Background(), "user@absent.example")
	if !errors.Is(err, ErrDomainNoMX) {
		t.Errorf("cached not-found must return ErrDomainNoMX, got %v", err)
	}
	if got := stub.calls(); got != 1 {
		t.Errorf("resolver must be called once across two lookups, got %d", got)
	}
}

// TestVerifyDomain_timeoutStaysSoft: a lookup failure with no NXDOMAIN/NODATA
// signal — a timeout, SERVFAIL, transport error — is not authoritative "no
// mail". It stays in the soft-failure bucket (ErrDomainUnresolvable) so the
// caller does not block the user. The not-found classification above must
// not bleed into this case.
func TestVerifyDomain_timeoutStaysSoft(t *testing.T) {
	stub := newStub(nil, &net.DNSError{IsTimeout: true})
	m := newMod(t)
	m.resolver = stub

	err := m.VerifyDomain(context.Background(), "user@slow.example")
	if !errors.Is(err, ErrDomainUnresolvable) {
		t.Errorf("IsTimeout must be classified as ErrDomainUnresolvable, got %v", err)
	}
	if errors.Is(err, ErrDomainNoMX) {
		t.Error("IsTimeout must NOT be classified as ErrDomainNoMX")
	}
}

// TestVerifyDomain_secondCallerKeepsItsDeadline covers the singleflight
// deadline leak: when caller A starts a slow lookup, caller B's short
// deadline must still bound B's wait. B must return DeadlineExceeded while
// A is still in flight, and the resolver must still be called only once
// (the in-flight call is A's, B never reaches the resolver).
//
// Ordering uses channels exclusively. Every channel receive has a bounded
// timeout so a regression cannot hang the package.
func TestVerifyDomain_secondCallerKeepsItsDeadline(t *testing.T) {
	stub := withBlockingStub([]*net.MX{{Host: "mail.example.com.", Pref: 10}}, nil)
	m := newMod(t)
	m.resolver = stub

	// Caller A: live context, starts the lookup.
	firstErr := make(chan error, 1)
	go func() {
		firstErr <- m.VerifyDomain(context.Background(), "user@example.com")
	}()

	// Wait for caller A's lookup to reach the resolver.
	select {
	case <-stub.started:
	case <-time.After(2 * time.Second):
		t.Fatal("first caller never reached the resolver")
	}

	// Caller B: a deadline already in the past. The lookup is singleflighted
	// behind A's, so B's context cancellation must short-circuit B's wait.
	deadline := time.Now().Add(-time.Second)
	ctxB, cancelB := context.WithDeadline(context.Background(), deadline)
	defer cancelB()

	// Run B in a goroutine with a bound: if the control regresses, B blocks on
	// A's lookup forever, and a hung package is a worse signal than a red test.
	type bResult struct {
		err     error
		elapsed time.Duration
	}
	bDone := make(chan bResult, 1)
	go func() {
		start := time.Now()
		err := m.VerifyDomain(ctxB, "user@example.com")
		bDone <- bResult{err, time.Since(start)}
	}()

	var errB error
	var elapsedB time.Duration
	select {
	case r := <-bDone:
		errB, elapsedB = r.err, r.elapsed
	case <-time.After(5 * time.Second):
		close(stub.release)
		t.Fatal("second caller blocked on the first caller's lookup instead of honouring its own deadline")
	}

	if !errors.Is(errB, context.DeadlineExceeded) {
		t.Errorf("second caller must return DeadlineExceeded, got %v", errB)
	}
	// B's deadline was already past, so its return should be prompt, with no
	// more than a small scheduling margin beyond the actual wait.
	if elapsedB > 500*time.Millisecond {
		t.Errorf("second caller blocked %v past its own deadline", elapsedB)
	}

	// A's lookup is still in flight; the resolver must have been called
	// exactly once. Caller B's short-circuit path must NOT have triggered
	// a second LookupMX call.
	if got := stub.calls(); got != 1 {
		t.Errorf("resolver must be called once (singleflight), got %d", got)
	}

	// Release caller A's lookup and verify it eventually returns success.
	close(stub.release)
	select {
	case errA := <-firstErr:
		if errA != nil {
			t.Errorf("first caller must succeed once released, got %v", errA)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first caller never returned after release")
	}
}
