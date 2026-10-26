// Package interop checks the JWT module against an independent reference
// verifier and foreign signers.
package interop

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/jwt"
	"github.com/Glyndor/authcore/tests/hostile/jwt/hostiletest"
)

func policy(e *hostiletest.Env, typ string) hostiletest.RefPolicy {
	return hostiletest.RefPolicy{
		Issuer:   jwt.DefaultConfig().Issuer,
		Audience: jwt.DefaultConfig().Audience[0],
		Typ:      typ,
		Kid:      e.Kid,
		Pub:      e.Pub,
		Now:      time.Now(),
	}
}

// Tokens the module issues are valid JWS tokens to a verifier that shares
// nothing with it: the header names EdDSA and the key id, the signature checks
// over the exact signing input, and the claims are what the Config says.
func TestHostile_Interop_issuedTokensVerifyUnderAnIndependentVerifier(t *testing.T) {
	e := hostiletest.NewEnv(t)
	cfg := jwt.Config{
		Issuer:          "https://auth.example",
		Audience:        []string{"https://api.example", "https://other.example"},
		AccessTokenTTL:  7 * time.Minute,
		RefreshTokenTTL: 3 * time.Hour,
	}
	m := e.Module(t, cfg)
	pair, err := m.CreateTokens(strings.ToUpper(hostiletest.Subject), hostiletest.Extra{Role: "rôle 日本 \"quoted\""})
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := m.RotateTokens(pair.RefreshToken, hostiletest.Extra{Role: "after"})
	if err != nil {
		t.Fatal(err)
	}

	for name, tc := range map[string]struct{ token, typ string }{
		"access":            {pair.AccessToken, "access"},
		"refresh":           {pair.RefreshToken, "refresh"},
		"rotated access":    {rotated.AccessToken, "access"},
		"rotated refresh":   {rotated.RefreshToken, "refresh"},
		"access (reversed)": {pair.AccessToken, "refresh"},
	} {
		p := policy(e, tc.typ)
		p.Issuer, p.Audience = cfg.Issuer, cfg.Audience[0]
		err := hostiletest.RefVerify(tc.token, p)
		wantOK := name != "access (reversed)"
		if wantOK && err != nil {
			t.Errorf("%s: the independent verifier refused it: %v", name, err)
		}
		if !wantOK && err == nil {
			t.Errorf("%s: the independent verifier accepted a token of the other type", name)
		}
	}

	// Claim values as the independent decoder reads them.
	var c map[string]any
	payload := strings.Split(pair.AccessToken, ".")[1]
	raw, _ := base64.RawURLEncoding.DecodeString(payload)
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	if got := c["sub"]; got != hostiletest.Subject {
		t.Errorf("sub = %v, want the lower-cased %q", got, hostiletest.Subject)
	}
	if aud, _ := c["aud"].([]any); len(aud) != 2 || aud[0] != cfg.Audience[0] || aud[1] != cfg.Audience[1] {
		t.Errorf("aud = %v, want both configured audiences in order", c["aud"])
	}
	iat, exp := c["iat"].(float64), c["exp"].(float64)
	if exp-iat != cfg.AccessTokenTTL.Seconds() {
		t.Errorf("exp-iat = %v, want %v", exp-iat, cfg.AccessTokenTTL.Seconds())
	}
	if h := hostiletest.DecodeHeader(t, pair.AccessToken); h["alg"] != "EdDSA" || h["typ"] != "JWT" || len(h) != 3 {
		t.Errorf("header = %v, want exactly alg, typ and kid", h)
	}
	if extraClaim, _ := c["extra"].(map[string]any); extraClaim["role"] != "rôle 日本 \"quoted\"" {
		t.Errorf("extra = %v, lost its text", c["extra"])
	}
}

// Tokens made by another implementation, with the boundary values of each
// claim, get the same verdict from the module as from the independent
// verifier. A disagreement is either side being too strict or too lenient at
// a boundary where the other is right.
func TestHostile_Interop_moduleAndReferenceAgreeOnClaimBoundaries(t *testing.T) {
	e := hostiletest.NewEnv(t)
	m := e.Module(t, jwt.Config{})
	now := time.Now()
	ours := jwt.DefaultConfig().Audience[0]
	const (
		v4       = "0191b432-b5a7-4c4f-b2e6-7a3f1d2e0001"
		badVar   = "0191b432-b5a7-7c4f-c2e6-7a3f1d2e0001"
		upperSub = "0191B432-B5A7-7C4F-B2E6-7A3F1D2E0001"
	)
	cases := map[string]map[string]any{
		"control":               hostiletest.ClaimsFor("access"),
		"aud string":            hostiletest.With(hostiletest.ClaimsFor("access"), "aud", ours),
		"aud array":             hostiletest.With(hostiletest.ClaimsFor("access"), "aud", []any{ours}),
		"aud second entry":      hostiletest.With(hostiletest.ClaimsFor("access"), "aud", []any{"x", ours}),
		"aud other":             hostiletest.With(hostiletest.ClaimsFor("access"), "aud", "other"),
		"aud empty array":       hostiletest.With(hostiletest.ClaimsFor("access"), "aud", []any{}),
		"aud empty string":      hostiletest.With(hostiletest.ClaimsFor("access"), "aud", ""),
		"aud missing":           hostiletest.With(hostiletest.ClaimsFor("access"), "aud", nil),
		"aud number":            hostiletest.With(hostiletest.ClaimsFor("access"), "aud", 7),
		"aud mixed array":       hostiletest.With(hostiletest.ClaimsFor("access"), "aud", []any{ours, 7}),
		"aud nested array":      hostiletest.With(hostiletest.ClaimsFor("access"), "aud", []any{[]any{ours}}),
		"aud other case":        hostiletest.With(hostiletest.ClaimsFor("access"), "aud", strings.ToUpper(ours)),
		"aud trailing slash":    hostiletest.With(hostiletest.ClaimsFor("access"), "aud", ours+"/"),
		"iss other case":        hostiletest.With(hostiletest.ClaimsFor("access"), "iss", strings.ToUpper(jwt.DefaultConfig().Issuer)),
		"iss missing":           hostiletest.With(hostiletest.ClaimsFor("access"), "iss", nil),
		"iss array":             hostiletest.With(hostiletest.ClaimsFor("access"), "iss", []any{jwt.DefaultConfig().Issuer}),
		"sub uppercase v7":      hostiletest.With(hostiletest.ClaimsFor("access"), "sub", upperSub),
		"sub version 4":         hostiletest.With(hostiletest.ClaimsFor("access"), "sub", v4),
		"sub bad variant":       hostiletest.With(hostiletest.ClaimsFor("access"), "sub", badVar),
		"sub trailing space":    hostiletest.With(hostiletest.ClaimsFor("access"), "sub", hostiletest.Subject+" "),
		"sub missing":           hostiletest.With(hostiletest.ClaimsFor("access"), "sub", nil),
		"jti version 4":         hostiletest.With(hostiletest.ClaimsFor("access"), "jti", v4),
		"jti missing":           hostiletest.With(hostiletest.ClaimsFor("access"), "jti", nil),
		"jti number":            hostiletest.With(hostiletest.ClaimsFor("access"), "jti", 7),
		"exp one minute":        hostiletest.With(hostiletest.ClaimsFor("access"), "exp", now.Add(time.Minute).Unix()),
		"exp past":              hostiletest.With(hostiletest.ClaimsFor("access"), "exp", now.Add(-time.Minute).Unix()),
		"exp float future":      hostiletest.With(hostiletest.ClaimsFor("access"), "exp", float64(now.Add(time.Minute).Unix())+0.5),
		"exp exponent form":     hostiletest.With(hostiletest.ClaimsFor("access"), "exp", json.Number("4.1e9")),
		"exp boolean":           hostiletest.With(hostiletest.ClaimsFor("access"), "exp", true),
		"exp null":              hostiletest.With(hostiletest.ClaimsFor("access"), "exp", json.RawMessage("null")),
		"exp missing":           hostiletest.With(hostiletest.ClaimsFor("access"), "exp", nil),
		"iat future":            hostiletest.With(hostiletest.ClaimsFor("access"), "iat", now.Add(time.Minute).Unix()),
		"iat missing":           hostiletest.With(hostiletest.ClaimsFor("access"), "iat", nil),
		"iat string":            hostiletest.With(hostiletest.ClaimsFor("access"), "iat", "yesterday"),
		"nbf future":            hostiletest.With(hostiletest.ClaimsFor("access"), "nbf", now.Add(time.Minute).Unix()),
		"nbf past":              hostiletest.With(hostiletest.ClaimsFor("access"), "nbf", now.Add(-time.Minute).Unix()),
		"nbf string":            hostiletest.With(hostiletest.ClaimsFor("access"), "nbf", "soon"),
		"type refresh":          hostiletest.ClaimsFor("refresh"),
		"type uppercase":        hostiletest.With(hostiletest.ClaimsFor("access"), "type", "ACCESS"),
		"type missing":          hostiletest.With(hostiletest.ClaimsFor("access"), "type", nil),
		"unknown claim":         hostiletest.With(hostiletest.ClaimsFor("access"), "admin", true),
		"unicode extra":         hostiletest.With(hostiletest.ClaimsFor("access"), "extra", map[string]any{"role": "\u202e\u0000\U0001f600"}),
		"extra with empty role": hostiletest.With(hostiletest.ClaimsFor("access"), "extra", map[string]any{}),
	}
	for name, claims := range cases {
		t.Run(name, func(t *testing.T) {
			token := e.SignEdDSA(t, nil, claims)
			refErr := hostiletest.RefVerify(token, policy(e, "access"))
			_, modErr := m.VerifyAccessToken(token)
			if (refErr == nil) != (modErr == nil) {
				t.Fatalf("reference: %v; module: %v; the two disagree", refErr, modErr)
			}
		})
	}
}

// The one place the module is more lenient than RFC 7519 section 2: a date
// written as a JSON string holding a number is read as that date (encoding/json
// decodes json.Number from a quoted number). The independent verifier, which
// requires a JSON number, refuses it. The date is still enforced, which the
// claim_types test pins; this test pins the divergence itself so that a change
// on either side is noticed. Only a holder of the signing key can write such a
// token, which the module never does.
func TestHostile_Interop_quotedNumericDateIsTheKnownLeniency(t *testing.T) {
	e := hostiletest.NewEnv(t)
	m := e.Module(t, jwt.Config{})
	token := e.SignEdDSA(t, nil, hostiletest.With(hostiletest.ClaimsFor("access"), "exp", hostiletest.Itoa(time.Now().Add(time.Minute).Unix())))
	if err := hostiletest.RefVerify(token, policy(e, "access")); err == nil {
		t.Error("the independent verifier accepted a quoted exp")
	}
	if _, err := m.VerifyAccessToken(token); err != nil {
		t.Errorf("the module refused a quoted exp in the future: %v; update the claim_types test and the docs if this is deliberate", err)
	}
}

// The other direction for the key: a token the independent code signs with the
// same private key is accepted, and one signed with any other key is not.
func TestHostile_Interop_foreignSignerIsAcceptedOnlyWithOurKey(t *testing.T) {
	e := hostiletest.NewEnv(t)
	m := e.Module(t, jwt.Config{})
	claims := hostiletest.ClaimsFor("access")

	sign := func(priv ed25519.PrivateKey) string {
		head := hostiletest.B64(`{"alg":"EdDSA","kid":"` + e.Kid + `","typ":"JWT"}`)
		raw, _ := json.Marshal(claims)
		in := head + "." + base64.RawURLEncoding.EncodeToString(raw)
		return in + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(in)))
	}
	if _, err := m.VerifyAccessToken(sign(e.Priv)); err != nil {
		t.Fatalf("a token signed by independent code with our key was refused: %v", err)
	}
	_, other, _ := ed25519.GenerateKey(nil)
	if c, err := m.VerifyAccessToken(sign(other)); err == nil {
		t.Fatalf("a token signed with another key was accepted: %+v", c)
	}
}
