package jwt

import (
	"context"
	"errors"
	"testing"
)

// stubDenylist is a programmable Denylist for tests.
type stubDenylist struct {
	revoked bool
	err     error
	gotJTI  string
	calls   int
}

func (s *stubDenylist) IsRevoked(_ context.Context, jti string) (bool, error) {
	s.calls++
	s.gotJTI = jti
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

func TestVerifyAccessTokenContext_passesContext(t *testing.T) {
	stub := &stubDenylist{}
	j := jwtWithDenylist(t, stub)
	pair, _ := j.CreateTokens(testSubject, struct{}{})

	ctx := context.Background()
	if _, err := j.VerifyAccessTokenContext(ctx, pair.AccessToken); err != nil {
		t.Fatalf("VerifyAccessTokenContext error = %v", err)
	}
	if stub.calls != 1 {
		t.Errorf("denylist calls = %d, want 1", stub.calls)
	}
}
