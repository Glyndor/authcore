package jwt_test

import (
	"errors"
	"testing"

	"github.com/Glyndor/authcore/auth/jwt"
)

// An access token is short-lived and travels on every request, a refresh
// token is long-lived and mints new pairs. Using one in the other's place is
// the privilege escalation: each path names the wrong-type refusal.
func TestHostile_TokenType_accessAndRefreshAreNotInterchangeable(t *testing.T) {
	e := newEnv(t)
	m := e.module(t, jwt.Config{})
	pair, err := m.CreateTokens(subject, extra{Role: "user"})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := m.VerifyAccessToken(pair.AccessToken); err != nil {
		t.Fatalf("control: access token as access: %v", err)
	}
	if _, err := m.RotateTokens(pair.RefreshToken, extra{}); err != nil {
		t.Fatalf("control: refresh token as refresh: %v", err)
	}

	if c, err := m.VerifyAccessToken(pair.RefreshToken); c != nil || !errors.Is(err, jwt.ErrWrongTokenType) {
		t.Fatalf("refresh token as access = %+v, %v; want ErrWrongTokenType", c, err)
	}
	if p, err := m.RotateTokens(pair.AccessToken, extra{Role: "admin"}); p != nil || !errors.Is(err, jwt.ErrWrongTokenType) {
		t.Fatalf("access token as refresh = %+v, %v; want ErrWrongTokenType", p, err)
	}
}

// The type claim is compared exactly. Near misses are refused on the path they
// target and are never read as the other kind.
func TestHostile_TokenType_nearMissesAreRefused(t *testing.T) {
	e := newEnv(t)
	m := e.module(t, jwt.Config{})

	for name, typ := range map[string]any{
		"uppercase":      "ACCESS",
		"trailing space": "access ",
		"leading space":  " access",
		"trailing NUL":   "access\x00",
		"empty":          "",
		"missing":        nil,
		"number":         1,
		"array":          []any{"access"},
		"object":         map[string]any{"access": true},
		"refresh":        "refresh",
		"other":          "id",
	} {
		t.Run("access/"+name, func(t *testing.T) {
			token := e.signEdDSA(t, nil, with(claimsFor("access"), "type", typ))
			if c, err := m.VerifyAccessToken(token); c != nil || err == nil {
				t.Fatalf("VerifyAccessToken accepted type %v: %+v", typ, c)
			}
		})
	}
	for name, typ := range map[string]any{
		"uppercase": "REFRESH",
		"missing":   nil,
		"access":    "access",
		"array":     []any{"refresh"},
	} {
		t.Run("refresh/"+name, func(t *testing.T) {
			token := e.signEdDSA(t, nil, with(claimsFor("refresh"), "type", typ))
			if p, err := m.RotateTokens(token, extra{}); p != nil || err == nil {
				t.Fatalf("RotateTokens accepted type %v", typ)
			}
		})
	}
}

// A payload with the same key twice is read differently by different parsers.
// Whichever copy this module honours, one token never verifies as both kinds.
func TestHostile_TokenType_duplicateTypeKey(t *testing.T) {
	e := newEnv(t)
	m := e.module(t, jwt.Config{})
	ts := claimsFor("access")
	payload := func(first, second string) string {
		return `{"iss":"` + jwt.DefaultConfig().Issuer + `","aud":["` + jwt.DefaultConfig().Audience[0] + `"],"sub":"` + subject +
			`","jti":"` + jtiA + `","iat":` + itoa(ts["iat"]) + `,"exp":` + itoa(ts["exp"]) + `,"type":"` + first + `","type":"` + second + `"}`
	}
	for name, tc := range map[string]struct{ first, second string }{
		"access then refresh": {"access", "refresh"},
		"refresh then access": {"refresh", "access"},
	} {
		t.Run(name, func(t *testing.T) {
			token := e.signRaw(t, payload(tc.first, tc.second))
			asAccess, errA := m.VerifyAccessToken(token)
			asRefresh, errR := m.RotateTokens(token, extra{})
			if asAccess != nil && asRefresh != nil {
				t.Fatalf("one token verified as both kinds: access err=%v, refresh err=%v", errA, errR)
			}
		})
	}
}
