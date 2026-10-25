package jwt_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/jwt"
)

func (e *env) policy(typ string) refPolicy {
	return refPolicy{
		issuer:   jwt.DefaultConfig().Issuer,
		audience: jwt.DefaultConfig().Audience[0],
		typ:      typ,
		kid:      e.kid,
		pub:      e.pub,
		now:      time.Now(),
	}
}

// Tokens the module issues are valid JWS tokens to a verifier that shares
// nothing with it: the header names EdDSA and the key id, the signature checks
// over the exact signing input, and the claims are what the Config says.
func TestHostile_Interop_issuedTokensVerifyUnderAnIndependentVerifier(t *testing.T) {
	e := newEnv(t)
	cfg := jwt.Config{
		Issuer:          "https://auth.example",
		Audience:        []string{"https://api.example", "https://other.example"},
		AccessTokenTTL:  7 * time.Minute,
		RefreshTokenTTL: 3 * time.Hour,
	}
	m := e.module(t, cfg)
	pair, err := m.CreateTokens(strings.ToUpper(subject), extra{Role: "rôle 日本 \"quoted\""})
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := m.RotateTokens(pair.RefreshToken, extra{Role: "after"})
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
		p := e.policy(tc.typ)
		p.issuer, p.audience = cfg.Issuer, cfg.Audience[0]
		err := refVerify(tc.token, p)
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
	if got := c["sub"]; got != subject {
		t.Errorf("sub = %v, want the lower-cased %q", got, subject)
	}
	if aud, _ := c["aud"].([]any); len(aud) != 2 || aud[0] != cfg.Audience[0] || aud[1] != cfg.Audience[1] {
		t.Errorf("aud = %v, want both configured audiences in order", c["aud"])
	}
	iat, exp := c["iat"].(float64), c["exp"].(float64)
	if exp-iat != cfg.AccessTokenTTL.Seconds() {
		t.Errorf("exp-iat = %v, want %v", exp-iat, cfg.AccessTokenTTL.Seconds())
	}
	if h := decodeHeader(t, pair.AccessToken); h["alg"] != "EdDSA" || h["typ"] != "JWT" || len(h) != 3 {
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
	e := newEnv(t)
	m := e.module(t, jwt.Config{})
	now := time.Now()
	ours := jwt.DefaultConfig().Audience[0]
	const (
		v4       = "0191b432-b5a7-4c4f-b2e6-7a3f1d2e0001"
		badVar   = "0191b432-b5a7-7c4f-c2e6-7a3f1d2e0001"
		upperSub = "0191B432-B5A7-7C4F-B2E6-7A3F1D2E0001"
	)
	cases := map[string]map[string]any{
		"control":               claimsFor("access"),
		"aud string":            with(claimsFor("access"), "aud", ours),
		"aud array":             with(claimsFor("access"), "aud", []any{ours}),
		"aud second entry":      with(claimsFor("access"), "aud", []any{"x", ours}),
		"aud other":             with(claimsFor("access"), "aud", "other"),
		"aud empty array":       with(claimsFor("access"), "aud", []any{}),
		"aud empty string":      with(claimsFor("access"), "aud", ""),
		"aud missing":           with(claimsFor("access"), "aud", nil),
		"aud number":            with(claimsFor("access"), "aud", 7),
		"aud mixed array":       with(claimsFor("access"), "aud", []any{ours, 7}),
		"aud nested array":      with(claimsFor("access"), "aud", []any{[]any{ours}}),
		"aud other case":        with(claimsFor("access"), "aud", strings.ToUpper(ours)),
		"aud trailing slash":    with(claimsFor("access"), "aud", ours+"/"),
		"iss other case":        with(claimsFor("access"), "iss", strings.ToUpper(jwt.DefaultConfig().Issuer)),
		"iss missing":           with(claimsFor("access"), "iss", nil),
		"iss array":             with(claimsFor("access"), "iss", []any{jwt.DefaultConfig().Issuer}),
		"sub uppercase v7":      with(claimsFor("access"), "sub", upperSub),
		"sub version 4":         with(claimsFor("access"), "sub", v4),
		"sub bad variant":       with(claimsFor("access"), "sub", badVar),
		"sub trailing space":    with(claimsFor("access"), "sub", subject+" "),
		"sub missing":           with(claimsFor("access"), "sub", nil),
		"jti version 4":         with(claimsFor("access"), "jti", v4),
		"jti missing":           with(claimsFor("access"), "jti", nil),
		"jti number":            with(claimsFor("access"), "jti", 7),
		"exp one minute":        with(claimsFor("access"), "exp", now.Add(time.Minute).Unix()),
		"exp past":              with(claimsFor("access"), "exp", now.Add(-time.Minute).Unix()),
		"exp float future":      with(claimsFor("access"), "exp", float64(now.Add(time.Minute).Unix())+0.5),
		"exp exponent form":     with(claimsFor("access"), "exp", json.Number("4.1e9")),
		"exp boolean":           with(claimsFor("access"), "exp", true),
		"exp null":              with(claimsFor("access"), "exp", json.RawMessage("null")),
		"exp missing":           with(claimsFor("access"), "exp", nil),
		"iat future":            with(claimsFor("access"), "iat", now.Add(time.Minute).Unix()),
		"iat missing":           with(claimsFor("access"), "iat", nil),
		"iat string":            with(claimsFor("access"), "iat", "yesterday"),
		"nbf future":            with(claimsFor("access"), "nbf", now.Add(time.Minute).Unix()),
		"nbf past":              with(claimsFor("access"), "nbf", now.Add(-time.Minute).Unix()),
		"nbf string":            with(claimsFor("access"), "nbf", "soon"),
		"type refresh":          claimsFor("refresh"),
		"type uppercase":        with(claimsFor("access"), "type", "ACCESS"),
		"type missing":          with(claimsFor("access"), "type", nil),
		"unknown claim":         with(claimsFor("access"), "admin", true),
		"unicode extra":         with(claimsFor("access"), "extra", map[string]any{"role": "\u202e\u0000\U0001f600"}),
		"extra with empty role": with(claimsFor("access"), "extra", map[string]any{}),
	}
	for name, claims := range cases {
		t.Run(name, func(t *testing.T) {
			token := e.signEdDSA(t, nil, claims)
			refErr := refVerify(token, e.policy("access"))
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
	e := newEnv(t)
	m := e.module(t, jwt.Config{})
	token := e.signEdDSA(t, nil, with(claimsFor("access"), "exp", itoa(time.Now().Add(time.Minute).Unix())))
	if err := refVerify(token, e.policy("access")); err == nil {
		t.Error("the independent verifier accepted a quoted exp")
	}
	if _, err := m.VerifyAccessToken(token); err != nil {
		t.Errorf("the module refused a quoted exp in the future: %v; update the claim_types test and the docs if this is deliberate", err)
	}
}

// The other direction for the key: a token the independent code signs with the
// same private key is accepted, and one signed with any other key is not.
func TestHostile_Interop_foreignSignerIsAcceptedOnlyWithOurKey(t *testing.T) {
	e := newEnv(t)
	m := e.module(t, jwt.Config{})
	claims := claimsFor("access")

	sign := func(priv ed25519.PrivateKey) string {
		head := b64(`{"alg":"EdDSA","kid":"` + e.kid + `","typ":"JWT"}`)
		raw, _ := json.Marshal(claims)
		in := head + "." + base64.RawURLEncoding.EncodeToString(raw)
		return in + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(in)))
	}
	if _, err := m.VerifyAccessToken(sign(e.priv)); err != nil {
		t.Fatalf("a token signed by independent code with our key was refused: %v", err)
	}
	_, other, _ := ed25519.GenerateKey(nil)
	if c, err := m.VerifyAccessToken(sign(other)); err == nil {
		t.Fatalf("a token signed with another key was accepted: %+v", c)
	}
}
