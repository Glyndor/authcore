package jwt_test

import (
	"errors"
	"strings"
	"testing"

	gjwt "github.com/golang-jwt/jwt/v5"

	"github.com/Glyndor/authcore/auth/jwt"
)

// The adversary holds a valid signature (the token is signed by the real key)
// and controls only the kid header. The kid picks which key verifies, so a
// kid that is not exactly one of the trusted ids must never verify.
func TestHostile_KidInjection_onlyAnExactTrustedKidVerifies(t *testing.T) {
	e := newEnv(t)
	m := e.module(t, jwt.Config{})

	if _, err := m.VerifyAccessToken(e.signEdDSA(t, nil, claimsFor("access"))); err != nil {
		t.Fatalf("control token with the real kid refused: %v", err)
	}

	cases := map[string]any{
		"kid removed":       nil,
		"empty kid":         "",
		"uppercased kid":    strings.ToUpper(e.kid),
		"kid plus space":    e.kid + " ",
		"kid plus NUL":      e.kid + "\x00",
		"kid plus newline":  e.kid + "\n",
		"kid prefix":        e.kid[:len(e.kid)-1],
		"kid doubled":       e.kid + e.kid,
		"path traversal":    "../../etc/passwd",
		"sql fragment":      "' OR '1'='1",
		"json object":       map[string]any{"kid": e.kid},
		"json array":        []any{e.kid},
		"number":            1,
		"bool":              true,
		"huge kid":          strings.Repeat("A", 4000),
		"unicode lookalike": strings.Replace(e.kid, "a", "\u0430", 1) + "\u0430",
	}
	for name, kid := range cases {
		t.Run(name, func(t *testing.T) {
			var hdr map[string]any
			if kid == nil {
				hdr = map[string]any{"kid": nil}
			} else {
				hdr = map[string]any{"kid": kid}
			}
			token := e.signEdDSA(t, hdr, claimsFor("access"))
			c, err := m.VerifyAccessToken(token)
			if c != nil || !errors.Is(err, jwt.ErrTokenInvalid) {
				t.Fatalf("VerifyAccessToken = %+v, %v; want nil and ErrTokenInvalid", c, err)
			}
		})
	}
}

// Header fields that tell a lenient verifier where to find a key, or what to
// do with the token, are ignored: the verifier trusts its own key set only.
// The attacker signs with a key of their own and ships it inside the token.
func TestHostile_HeaderInjection_embeddedKeysAndLocatorsAreNotTrusted(t *testing.T) {
	e := newEnv(t)
	attacker := newEnv(t)
	m := e.module(t, jwt.Config{})

	jwk := map[string]any{"kty": "OKP", "crv": "Ed25519", "x": b64(string(attacker.pub)), "kid": e.kid}
	cases := map[string]map[string]any{
		"embedded jwk":            {"jwk": jwk},
		"jku locator":             {"jku": "https://attacker.invalid/jwks.json"},
		"x5u locator":             {"x5u": "https://attacker.invalid/cert.pem"},
		"x5c chain":               {"x5c": []any{b64("not a certificate")}},
		"unknown crit extension":  {"crit": []any{"exp"}},
		"crit naming our header":  {"crit": []any{"kid"}},
		"typ none":                {"typ": "none"},
		"cty nested JWT":          {"cty": "JWT"},
		"zip bomb flag":           {"zip": "DEF"},
		"oversized custom header": {"x-pad": strings.Repeat("A", 3000)},
	}
	for name, hdr := range cases {
		t.Run(name, func(t *testing.T) {
			token := e.sign(t, gjwt.SigningMethodEdDSA, attacker.priv, hdr, claimsFor("access"))
			c, err := m.VerifyAccessToken(token)
			if c != nil || !errors.Is(err, jwt.ErrTokenInvalid) {
				t.Fatalf("VerifyAccessToken = %+v, %v; want nil and ErrTokenInvalid", c, err)
			}
		})
	}
}
