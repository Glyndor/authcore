package rotation_test

import (
	"errors"
	"testing"
	"time"

	gjwt "github.com/golang-jwt/jwt/v5"

	"github.com/Glyndor/authcore/auth/jwt/internal/claims"
	"github.com/Glyndor/authcore/auth/jwt/internal/issue"
	"github.com/Glyndor/authcore/auth/jwt/internal/jwterr"
	"github.com/Glyndor/authcore/auth/jwt/internal/jwttest"
	"github.com/Glyndor/authcore/auth/jwt/internal/tokenid"
)

// Controls the 2026-09-25 review found working but unpinned.

// The refresh path refuses a token with no exp, and one issued in the
// future, for those reasons. Both verifiers share parserOptions since #473;
// these pin the refresh side on its own.
func TestRotateTokens_refusesMissingExpAndFutureIat(t *testing.T) {
	j := newRig[struct{}](t, jwttest.DefaultConfig())
	now := j.Now
	jti, err := tokenid.NewJTI(now)
	if err != nil {
		t.Fatal(err)
	}
	rid, err := tokenid.NewRID()
	if err != nil {
		t.Fatal(err)
	}
	// mapJWTError collapses the reason into ErrTokenInvalid, so the
	// untouched token rotating below is what shows each refusal was the
	// claim under test.
	for name, mutate := range map[string]func(*claims.Refresh){
		"no exp":     func(c *claims.Refresh) { c.ExpiresAt = nil },
		"future iat": func(c *claims.Refresh) { c.IssuedAt = gjwt.NewNumericDate(now.Add(24 * time.Hour)) },
	} {
		t.Run(name, func(t *testing.T) {
			rc := claims.NewRefresh(j.Cfg.Issuer, jwttest.Subject, jti, rid, j.Cfg.Audience, now, j.Cfg.RefreshTokenTTL)
			mutate(rc)
			tok, err := issue.SignToken(rc, j.K.Priv, j.K.KeyID())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := j.RotateTokens(tok, struct{}{}); !errors.Is(err, jwterr.ErrTokenInvalid) {
				t.Fatalf("RotateTokens = %v, want ErrTokenInvalid", err)
			}
		})
	}
	// The same claims untouched rotate.
	rc := claims.NewRefresh(j.Cfg.Issuer, jwttest.Subject, jti, rid, j.Cfg.Audience, now, j.Cfg.RefreshTokenTTL)
	tok, err := issue.SignToken(rc, j.K.Priv, j.K.KeyID())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.RotateTokens(tok, struct{}{}); err != nil {
		t.Fatalf("the untouched refresh token: %v", err)
	}
}

// The leeway applies to the refresh path: a refresh token verifies up to
// exp + leeway and not past it.
func TestRotateTokens_honoursTheLeeway(t *testing.T) {
	cfg := jwttest.DefaultConfig()
	cfg.ClockSkewLeeway = 30 * time.Second
	j := newRig[struct{}](t, cfg)
	pair, err := j.CreateTokens(jwttest.Subject, struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	j.Now = pair.RefreshTokenExpiresAt.Add(20 * time.Second)
	if _, err := j.RotateTokens(pair.RefreshToken, struct{}{}); err != nil {
		t.Fatalf("20 s past exp with a 30 s leeway: %v, want accepted", err)
	}
	j.Now = pair.RefreshTokenExpiresAt.Add(40 * time.Second)
	if _, err := j.RotateTokens(pair.RefreshToken, struct{}{}); !errors.Is(err, jwterr.ErrTokenExpired) {
		t.Fatalf("40 s past exp with a 30 s leeway: %v, want ErrTokenExpired", err)
	}
}
