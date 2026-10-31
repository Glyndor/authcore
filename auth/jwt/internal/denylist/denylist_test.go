package denylist_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/jwt/internal/denylist"
	"github.com/Glyndor/authcore/auth/jwt/internal/jwterr"
)

type stub struct {
	revoked bool
	err     error
	gotJTI  string
	calls   int
}

func (s *stub) IsRevoked(_ context.Context, jti string) (bool, error) {
	s.calls++
	s.gotJTI = jti
	return s.revoked, s.err
}

func TestContext_withoutADenylistIsUnbounded(t *testing.T) {
	ctx, cancel := denylist.Context(nil)
	defer cancel()

	if _, ok := ctx.Deadline(); ok {
		t.Error("with no denylist there is nothing to bound, want no deadline")
	}
}

func TestContext_withADenylistIsBoundedByTheDefaultTimeout(t *testing.T) {
	before := time.Now()
	ctx, cancel := denylist.Context(&stub{})
	defer cancel()

	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("a configured denylist must run under a deadline so a hung store cannot block forever")
	}
	if got := deadline.Sub(before); got > denylist.DefaultTimeout+time.Second || got < denylist.DefaultTimeout-time.Second {
		t.Errorf("deadline in %s, want about %s", got, denylist.DefaultTimeout)
	}
}

func TestCheck_aNilDenylistNeverRevokes(t *testing.T) {
	if err := denylist.Check(context.Background(), nil, "jti"); err != nil {
		t.Fatalf("Check(nil) = %v, want nil", err)
	}
}

// A store that ignores its context answers "not revoked" after the deadline
// has passed. That late "no" must not let the token through.
func TestCheck_aLateNotRevokedAnswerFailsClosed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	late := &lateStub{cancel: cancel}

	err := denylist.Check(ctx, late, "jti-1")
	if err == nil {
		t.Fatal("Check accepted on an answer given after the deadline, want an error")
	}
	if !errors.Is(err, context.Canceled) || errors.Is(err, jwterr.ErrTokenRevoked) {
		t.Fatalf("Check = %v, want the context error and no revocation", err)
	}
}

// A revocation that arrives late is still a revocation.
func TestCheck_aLateRevokedAnswerStillRevokes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	late := &lateStub{cancel: cancel, revoked: true}

	if err := denylist.Check(ctx, late, "jti-1"); !errors.Is(err, jwterr.ErrTokenRevoked) {
		t.Fatalf("Check = %v, want ErrTokenRevoked", err)
	}
}

// lateStub cancels the context it was given and answers anyway, the way a
// driver that does not watch its context behaves once the deadline fires.
type lateStub struct {
	cancel  context.CancelFunc
	revoked bool
}

func (l *lateStub) IsRevoked(context.Context, string) (bool, error) {
	l.cancel()
	return l.revoked, nil
}

func TestCheck_reportsRevocationAndStoreFailuresApart(t *testing.T) {
	s := &stub{}
	if err := denylist.Check(context.Background(), s, "jti-1"); err != nil {
		t.Fatalf("Check on an active session = %v, want nil", err)
	}
	if s.gotJTI != "jti-1" || s.calls != 1 {
		t.Errorf("store asked %d times about %q, want once about jti-1", s.calls, s.gotJTI)
	}

	s.revoked = true
	if err := denylist.Check(context.Background(), s, "jti-1"); !errors.Is(err, jwterr.ErrTokenRevoked) {
		t.Fatalf("Check on a revoked session = %v, want ErrTokenRevoked", err)
	}

	s.revoked = false
	cause := errors.New("redis down")
	s.err = cause
	err := denylist.Check(context.Background(), s, "jti-1")
	if !errors.Is(err, cause) || errors.Is(err, jwterr.ErrTokenRevoked) {
		t.Fatalf("Check with a failing store = %v, want the wrapped store error and no revocation", err)
	}
	if !strings.Contains(err.Error(), "denylist lookup") {
		t.Errorf("error %q must name the lookup", err)
	}
}
