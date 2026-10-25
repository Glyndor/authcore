package verify_test

import (
	"context"
	"errors"
	"testing"

	"github.com/Glyndor/authcore/auth/jwt/internal/jwterr"
	"github.com/Glyndor/authcore/auth/jwt/internal/jwttest"
	"github.com/Glyndor/authcore/auth/jwt/internal/verify"
)

func TestRefresh_acceptsARefreshTokenAndRefusesAnAccessToken(t *testing.T) {
	j := newRig[struct{}](t, jwttest.DefaultConfig())
	pair, err := j.CreateTokens(jwttest.Subject, struct{}{})
	if err != nil {
		t.Fatal(err)
	}

	c, err := verify.Refresh(context.Background(), j.VerifyParams(), j.Now, pair.RefreshToken)
	if err != nil || c.ID != pair.SessionID || c.Subject != jwttest.Subject {
		t.Fatalf("Refresh(refresh token) = %+v, %v; want the session's claims", c, err)
	}
	if _, err := verify.Refresh(context.Background(), j.VerifyParams(), j.Now, pair.AccessToken); !errors.Is(err, jwterr.ErrWrongTokenType) {
		t.Fatalf("Refresh(access token) = %v, want ErrWrongTokenType", err)
	}
}

func TestRefresh_asksTheDenylistAboutTheSession(t *testing.T) {
	stub := &stubDenylist{}
	j := jwtWithDenylist(t, stub)
	pair, err := j.CreateTokens(jwttest.Subject, struct{}{})
	if err != nil {
		t.Fatal(err)
	}

	stub.revoked = true
	if _, err := verify.Refresh(context.Background(), j.VerifyParams(), j.Now, pair.RefreshToken); !errors.Is(err, jwterr.ErrTokenRevoked) {
		t.Fatalf("Refresh on a revoked session = %v, want ErrTokenRevoked", err)
	}
	if stub.gotJTI != pair.SessionID {
		t.Fatalf("denylist asked about %q, want %q", stub.gotJTI, pair.SessionID)
	}
}
