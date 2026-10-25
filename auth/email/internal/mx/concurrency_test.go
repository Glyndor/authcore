package mx

import (
	"context"
	"errors"
	"net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/Glyndor/authcore/auth/email/internal/errs"
)

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
	m := newVerifier()
	m.resolver = stub

	// Caller A: live context, starts the lookup.
	firstErr := make(chan error, 1)
	go func() {
		firstErr <- m.Verify(context.Background(), "user@example.com")
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
		err := m.Verify(ctxB, "user@example.com")
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

// When the caller that started a shared lookup goes away, the lookup still
// finishes and the others get its real answer. It ran on that caller's
// context until 2026-09-25, so they got the soft "unresolvable" instead,
// cached for 30 seconds.
func TestVerifyDomain_theStartersCancellationDoesNotDecideForOthers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m := newVerifier()
		stub := withBlockingStub(nil, &net.DNSError{IsNotFound: true})
		m.resolver = stub

		ctxA, cancelA := context.WithCancel(context.Background())
		errA := make(chan error, 1)
		go func() { errA <- m.Verify(ctxA, "user@gone.example") }()
		<-stub.started

		errB := make(chan error, 1)
		go func() { errB <- m.Verify(context.Background(), "user@gone.example") }()
		synctest.Wait() // B has joined A's lookup

		cancelA()
		if err := <-errA; !errors.Is(err, context.Canceled) {
			t.Fatalf("the cancelled starter got %v, want context.Canceled", err)
		}
		close(stub.release)
		if err := <-errB; !errors.Is(err, errs.ErrDomainNoMX) {
			t.Fatalf("the joined caller got %v, want errs.ErrDomainNoMX", err)
		}
		if err := m.Verify(context.Background(), "user@gone.example"); !errors.Is(err, errs.ErrDomainNoMX) {
			t.Fatalf("a later caller got %v, want the cached errs.ErrDomainNoMX", err)
		}
		if n := stub.calls(); n != 1 {
			t.Fatalf("%d lookups, want 1", n)
		}
	})
}
