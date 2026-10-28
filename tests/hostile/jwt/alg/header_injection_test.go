package alg

import (
	"errors"
	"strings"
	"testing"

	gjwt "github.com/golang-jwt/jwt/v5"

	"github.com/Glyndor/authcore/auth/jwt"
	"github.com/Glyndor/authcore/tests/hostile/jwt/hostiletest"
)

// The adversary holds a valid signature (the token is signed by the real key)
// and controls only the kid header. The kid picks which key verifies, so a
// kid that is not exactly one of the trusted ids must never verify.
func TestHostile_KidInjection_onlyAnExactTrustedKidVerifies(t *testing.T) {
	e := hostiletest.NewEnv(t)
	// The kid is derived from a fresh random key. When it has no letter,
	// upper-casing it changes nothing and that token is the legitimate one, so
	// draw another key until the case variant is really a different string.
	for i := 0; i < 64 && strings.ToUpper(e.Kid) == e.Kid; i++ {
		e = hostiletest.NewEnv(t)
	}
	if strings.ToUpper(e.Kid) == e.Kid {
		t.Fatalf("no key with a lower-case letter in its kid after 64 draws: %q", e.Kid)
	}
	m := e.Module(t, jwt.Config{})

	if _, err := m.VerifyAccessToken(e.SignEdDSA(t, nil, hostiletest.ClaimsFor("access"))); err != nil {
		t.Fatalf("control token with the real kid refused: %v", err)
	}

	cases := map[string]any{
		"kid removed":       nil,
		"empty kid":         "",
		"uppercased kid":    strings.ToUpper(e.Kid),
		"kid plus space":    e.Kid + " ",
		"kid plus NUL":      e.Kid + "\x00",
		"kid plus newline":  e.Kid + "\n",
		"kid prefix":        e.Kid[:len(e.Kid)-1],
		"kid doubled":       e.Kid + e.Kid,
		"path traversal":    "../../etc/passwd",
		"sql fragment":      "' OR '1'='1",
		"json object":       map[string]any{"kid": e.Kid},
		"json array":        []any{e.Kid},
		"number":            1,
		"bool":              true,
		"huge kid":          strings.Repeat("A", 4000),
		"unicode lookalike": strings.Replace(e.Kid, "a", "\u0430", 1) + "\u0430",
	}
	for name, kid := range cases {
		t.Run(name, func(t *testing.T) {
			var hdr map[string]any
			if kid == nil {
				hdr = map[string]any{"kid": nil}
			} else {
				hdr = map[string]any{"kid": kid}
			}
			token := e.SignEdDSA(t, hdr, hostiletest.ClaimsFor("access"))
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
	e := hostiletest.NewEnv(t)
	attacker := hostiletest.NewEnv(t)
	m := e.Module(t, jwt.Config{})

	jwk := map[string]any{"kty": "OKP", "crv": "Ed25519", "x": hostiletest.B64(string(attacker.Pub)), "kid": e.Kid}
	cases := map[string]map[string]any{
		"embedded jwk":            {"jwk": jwk},
		"jku locator":             {"jku": "https://attacker.invalid/jwks.json"},
		"x5u locator":             {"x5u": "https://attacker.invalid/cert.pem"},
		"x5c chain":               {"x5c": []any{hostiletest.B64("not a certificate")}},
		"unknown crit extension":  {"crit": []any{"exp"}},
		"crit naming our header":  {"crit": []any{"kid"}},
		"typ none":                {"typ": "none"},
		"cty nested JWT":          {"cty": "JWT"},
		"zip bomb flag":           {"zip": "DEF"},
		"oversized custom header": {"x-pad": strings.Repeat("A", 3000)},
	}
	for name, hdr := range cases {
		t.Run(name, func(t *testing.T) {
			token := e.Sign(t, gjwt.SigningMethodEdDSA, attacker.Priv, hdr, hostiletest.ClaimsFor("access"))
			c, err := m.VerifyAccessToken(token)
			if c != nil || !errors.Is(err, jwt.ErrTokenInvalid) {
				t.Fatalf("VerifyAccessToken = %+v, %v; want nil and ErrTokenInvalid", c, err)
			}
		})
	}
}
