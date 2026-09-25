package jwt

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// Behaviour fixed on 2026-09-25, each refusal paired with the case that
// still works: a revoked session cannot be rotated, the leeway has a
// ceiling, a typed-nil Denylist is refused, a zero-value JWT refuses rather
// than panics, and an issued token has one spelling.

type ctxKey struct{}

func TestRotateTokens_refusesARevokedSession(t *testing.T) {
	p := newFakeProvider(t)
	stub := &stubDenylist{}
	cfg := DefaultConfig()
	cfg.Denylist = stub
	j := newTestJWT[struct{}](t, p, cfg)
	pair, err := j.CreateTokens(testSubject, struct{}{})
	if err != nil {
		t.Fatal(err)
	}

	stub.revoked = true
	if _, err := j.RotateTokens(pair.RefreshToken, struct{}{}); !errors.Is(err, ErrTokenRevoked) {
		t.Fatalf("RotateTokens on a revoked session = %v, want ErrTokenRevoked", err)
	}
	if stub.gotJTI != pair.SessionID {
		t.Fatalf("denylist asked about %q, want the session id %q", stub.gotJTI, pair.SessionID)
	}

	ctx := context.WithValue(context.Background(), ctxKey{}, "request")
	if _, err := j.RotateTokensContext(ctx, pair.RefreshToken, struct{}{}); !errors.Is(err, ErrTokenRevoked) {
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

func TestNew_boundsTheClockSkewLeeway(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ClockSkewLeeway = maxClockSkewLeeway
	if _, err := New[struct{}](newFakeProvider(t), cfg); err != nil {
		t.Fatalf("leeway at the ceiling: %v, want accepted", err)
	}
	cfg.ClockSkewLeeway = maxClockSkewLeeway + time.Nanosecond
	_, err := New[struct{}](newFakeProvider(t), cfg)
	if !errors.Is(err, ErrInvalidConfig) || !strings.Contains(err.Error(), "clock skew leeway must be at most") {
		t.Fatalf("leeway past the ceiling: %v, want ErrInvalidConfig naming the ceiling", err)
	}
}

func TestNew_refusesATypedNilDenylist(t *testing.T) {
	cfg := DefaultConfig()
	var disabled *stubDenylist
	cfg.Denylist = disabled
	_, err := New[struct{}](newFakeProvider(t), cfg)
	if !errors.Is(err, ErrInvalidConfig) || !strings.Contains(err.Error(), "denylist holds a nil") {
		t.Fatalf("typed-nil Denylist: %v, want ErrInvalidConfig", err)
	}
}

func TestZeroValueJWT_refusesInsteadOfPanicking(t *testing.T) {
	for name, j := range map[string]*JWT[struct{}]{"zero value": {}, "nil pointer": nil} {
		t.Run(name, func(t *testing.T) {
			if _, err := j.CreateTokens(testSubject, struct{}{}); !errors.Is(err, ErrNotInitialised) {
				t.Errorf("CreateTokens = %v", err)
			}
			if _, err := j.VerifyAccessToken("a.b.c"); !errors.Is(err, ErrNotInitialised) {
				t.Errorf("VerifyAccessToken = %v", err)
			}
			if _, err := j.VerifyAccessTokenContext(context.Background(), "a.b.c"); !errors.Is(err, ErrNotInitialised) {
				t.Errorf("VerifyAccessTokenContext = %v", err)
			}
			if _, err := j.RotateTokens("a.b.c", struct{}{}); !errors.Is(err, ErrNotInitialised) {
				t.Errorf("RotateTokens = %v", err)
			}
			if _, err := j.RotateTokensContext(context.Background(), "a.b.c", struct{}{}); !errors.Is(err, ErrNotInitialised) {
				t.Errorf("RotateTokensContext = %v", err)
			}
		})
	}
}
