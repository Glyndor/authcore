package jwt

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// stubDenylist is a programmable Denylist for tests.
type stubDenylist struct {
	revoked bool
	err     error
	gotJTI  string
	gotCtx  context.Context
	calls   int
}

func (s *stubDenylist) IsRevoked(ctx context.Context, jti string) (bool, error) {
	s.calls++
	s.gotJTI = jti
	s.gotCtx = ctx
	return s.revoked, s.err
}

func jwtWithDenylist(t *testing.T, d Denylist) *JWT[struct{}] {
	t.Helper()
	cfg := DefaultConfig()
	cfg.Denylist = d
	return newTestJWT[struct{}](t, newFakeProvider(t), cfg)
}

func TestVerifyAccessToken_denylistRevoked(t *testing.T) {
	stub := &stubDenylist{revoked: true}
	j := jwtWithDenylist(t, stub)
	pair, _ := j.CreateTokens(testSubject, struct{}{})

	_, err := j.VerifyAccessToken(pair.AccessToken)
	if !errors.Is(err, ErrTokenRevoked) {
		t.Fatalf("expected ErrTokenRevoked, got %v", err)
	}
	if stub.gotJTI != pair.SessionID {
		t.Errorf("denylist queried jti %q, want SessionID %q", stub.gotJTI, pair.SessionID)
	}
}

func TestVerifyAccessToken_denylistActive(t *testing.T) {
	stub := &stubDenylist{revoked: false}
	j := jwtWithDenylist(t, stub)
	pair, _ := j.CreateTokens(testSubject, struct{}{})

	if _, err := j.VerifyAccessToken(pair.AccessToken); err != nil {
		t.Fatalf("a non-revoked token must verify, got %v", err)
	}
	if stub.calls != 1 {
		t.Errorf("denylist calls = %d, want 1", stub.calls)
	}
}

func TestVerifyAccessToken_denylistErrorFailsClosed(t *testing.T) {
	sentinel := errors.New("redis down")
	j := jwtWithDenylist(t, &stubDenylist{err: sentinel})
	pair, _ := j.CreateTokens(testSubject, struct{}{})

	_, err := j.VerifyAccessToken(pair.AccessToken)
	if !errors.Is(err, sentinel) {
		t.Errorf("expected the wrapped store error, got %v", err)
	}
	if errors.Is(err, ErrTokenRevoked) {
		t.Error("a store error must not be reported as a clean revocation")
	}
}

func TestVerifyAccessToken_denylistNotCalledForInvalidToken(t *testing.T) {
	stub := &stubDenylist{}
	j := jwtWithDenylist(t, stub)

	// A garbage token fails signature/format before any denylist lookup.
	if _, err := j.VerifyAccessToken("not.a.jwt"); err == nil {
		t.Fatal("expected an error for a malformed token")
	}
	if stub.calls != 0 {
		t.Errorf("denylist must not be consulted for an invalid token; calls = %d", stub.calls)
	}
}

func TestVerifyAccessToken_noDenylistSkipsLookup(t *testing.T) {
	// Default config has no denylist; verification must not require one.
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	pair, _ := j.CreateTokens(testSubject, struct{}{})
	if _, err := j.VerifyAccessToken(pair.AccessToken); err != nil {
		t.Fatalf("verify without a denylist must succeed, got %v", err)
	}
}

// deadlineStub records whether the context it was handed carried a deadline.
type deadlineStub struct{ hadDeadline bool }

func (s *deadlineStub) IsRevoked(ctx context.Context, _ string) (bool, error) {
	_, s.hadDeadline = ctx.Deadline()
	return false, nil
}

func TestVerifyAccessToken_denylistRunsUnderDeadline(t *testing.T) {
	// The context-less convenience method must bound the denylist lookup with a
	// default timeout so a hung store cannot block forever.
	stub := &deadlineStub{}
	cfg := DefaultConfig()
	cfg.Denylist = stub
	j := newTestJWT[struct{}](t, newFakeProvider(t), cfg)
	pair, _ := j.CreateTokens(testSubject, struct{}{})

	if _, err := j.VerifyAccessToken(pair.AccessToken); err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}
	if !stub.hadDeadline {
		t.Error("denylist lookup should run under a deadline when called via VerifyAccessToken")
	}
}

func TestVerifyAccessToken_oversizedTokenRejected(t *testing.T) {
	j := newTestJWT[string](t, newFakeProvider(t), DefaultConfig())

	// Build an otherwise-valid access token whose signed length exceeds the
	// 8 KiB cap. The token's signature, issuer, audience, expiry and type
	// all check out; only the size disqualifies it.
	claims := newAccessClaims(j.cfg.Issuer, testSubject, "019600ab-0000-7000-8000-000000000099", j.cfg.Audience, strings.Repeat("a", 8192), epoch, j.cfg.AccessTokenTTL)
	claims.Type = tokenTypeAccess
	oversized := signAccessClaimsForTest(t, claims, j.priv, j.kid)

	_, err := j.VerifyAccessToken(oversized)
	if !errors.Is(err, ErrTokenOversized) {
		t.Errorf("expected ErrTokenOversized for an oversized but otherwise valid token, got %v", err)
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("error must name the failure shape, got %q", err.Error())
	}
}

// TestVerifyAccessToken_oversizedRawStringRejected keeps the original
// coverage: a string that is not a JWT at all and is also too long must be
// refused as oversized, not as malformed.
func TestVerifyAccessToken_oversizedRawStringRejected(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	oversized := strings.Repeat("a", 9000)
	if _, err := j.VerifyAccessToken(oversized); !errors.Is(err, ErrTokenOversized) {
		t.Errorf("expected ErrTokenOversized for an oversized non-JWT string, got %v", err)
	}
}

func TestVerifyAccessTokenContext_passesContext(t *testing.T) {
	stub := &stubDenylist{}
	j := jwtWithDenylist(t, stub)
	pair, _ := j.CreateTokens(testSubject, struct{}{})

	type ctxKey struct{}
	ctx := context.WithValue(context.Background(), ctxKey{}, "marker")
	if _, err := j.VerifyAccessTokenContext(ctx, pair.AccessToken); err != nil {
		t.Fatalf("VerifyAccessTokenContext error = %v", err)
	}
	if stub.calls != 1 {
		t.Errorf("denylist calls = %d, want 1", stub.calls)
	}
	if stub.gotCtx == nil {
		t.Fatal("denylist did not receive a context")
	}
	if got, _ := stub.gotCtx.Value(ctxKey{}).(string); got != "marker" {
		t.Errorf("denylist received the wrong context: marker = %q, want %q", got, "marker")
	}
}
