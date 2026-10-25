package rotation_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/jwt/internal/jwterr"
	"github.com/Glyndor/authcore/auth/jwt/internal/jwttest"
)

// Behaviour fixed on 2026-09-25, each refusal paired with the case that
// still works: a revoked session cannot be rotated.

// stubDenylist is a programmable Denylist for tests.
type stubDenylist struct {
	revoked bool
	err     error
	gotJTI  string
	gotCtx  context.Context
}

func (s *stubDenylist) IsRevoked(ctx context.Context, jti string) (bool, error) {
	s.gotJTI = jti
	s.gotCtx = ctx
	return s.revoked, s.err
}

type ctxKey struct{}

func TestRotateTokens_refusesARevokedSession(t *testing.T) {
	stub := &stubDenylist{}
	cfg := jwttest.DefaultConfig()
	cfg.Denylist = stub
	j := newRig[struct{}](t, cfg)
	pair, err := j.CreateTokens(jwttest.Subject, struct{}{})
	if err != nil {
		t.Fatal(err)
	}

	stub.revoked = true
	if _, err := j.RotateTokens(pair.RefreshToken, struct{}{}); !errors.Is(err, jwterr.ErrTokenRevoked) {
		t.Fatalf("RotateTokens on a revoked session = %v, want ErrTokenRevoked", err)
	}
	if stub.gotJTI != pair.SessionID {
		t.Fatalf("denylist asked about %q, want the session id %q", stub.gotJTI, pair.SessionID)
	}

	ctx := context.WithValue(context.Background(), ctxKey{}, "request")
	if _, err := j.RotateTokensContext(ctx, pair.RefreshToken, struct{}{}); !errors.Is(err, jwterr.ErrTokenRevoked) {
		t.Fatalf("RotateTokensContext on a revoked session = %v, want ErrTokenRevoked", err)
	}
	if stub.gotCtx.Value(ctxKey{}) != "request" {
		t.Fatal("RotateTokensContext did not pass the caller's context to the denylist")
	}

	stub.revoked = false
	if _, err := j.RotateTokens(pair.RefreshToken, struct{}{}); err != nil {
		t.Fatalf("RotateTokens on an active session = %v, want a new pair", err)
	}

	stub.err = errors.New("store unreachable")
	if _, err := j.RotateTokens(pair.RefreshToken, struct{}{}); err == nil || !strings.Contains(err.Error(), "denylist lookup") {
		t.Fatalf("RotateTokens with a failing store = %v, want the lookup error (fail closed)", err)
	}
}
