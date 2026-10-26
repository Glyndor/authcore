// Package alg attacks the JWT header: algorithm confusion, token type
// confusion, header injection and object keys that read two ways.
package alg

import (
	"errors"
	"testing"

	gjwt "github.com/golang-jwt/jwt/v5"

	"github.com/Glyndor/authcore/auth/jwt"
	"github.com/Glyndor/authcore/tests/hostile/jwt/hostiletest"
)

// An adversary who knows the algorithm list tries to choose it. The verifier
// accepts EdDSA and nothing else, whatever the header says.
func TestHostile_AlgConfusion_unsignedAndForeignAlgorithms(t *testing.T) {
	e := hostiletest.NewEnv(t)
	m := e.Module(t, jwt.Config{})

	good := e.SignEdDSA(t, nil, hostiletest.ClaimsFor("access"))
	if _, err := m.VerifyAccessToken(good); err != nil {
		t.Fatalf("control token refused: %v", err)
	}

	hdr := func(alg string) string { return hostiletest.B64(`{"alg":` + alg + `,"kid":"` + e.Kid + `"}`) }
	body := hostiletest.B64(`{"type":"access"}`)
	none := gjwt.UnsafeAllowNoneSignatureType

	cases := map[string]string{
		"alg none":                      e.Sign(t, gjwt.SigningMethodNone, none, nil, hostiletest.ClaimsFor("access")),
		"alg none, bare dot":            hdr(`"none"`) + "." + body + ".",
		"alg None casing":               hdr(`"None"`) + "." + body + ".",
		"HS256 keyed by pub key":        e.Sign(t, gjwt.SigningMethodHS256, []byte(e.Pub), nil, hostiletest.ClaimsFor("access")),
		"HS256 keyed by the seed":       e.Sign(t, gjwt.SigningMethodHS256, e.Priv.Seed(), nil, hostiletest.ClaimsFor("access")),
		"HS256 keyed by refresh secret": e.Sign(t, gjwt.SigningMethodHS256, e.Secret, nil, hostiletest.ClaimsFor("access")),
		"HS512 keyed by pub key":        e.Sign(t, gjwt.SigningMethodHS512, []byte(e.Pub), nil, hostiletest.ClaimsFor("access")),
		"EdDSA header, empty signature": hdr(`"EdDSA"`) + "." + body + ".",
		"alg eddsa lowercase":           hdr(`"eddsa"`) + "." + body + ".AAAA",
		"alg empty":                     hdr(`""`) + "." + body + ".AAAA",
		"alg array":                     hdr(`["EdDSA"]`) + "." + body + ".AAAA",
		"alg number":                    hdr(`1`) + "." + body + ".AAAA",
		"alg missing":                   hostiletest.B64(`{"kid":"`+e.Kid+`"}`) + "." + body + ".AAAA",
		"alg RS256 over EdDSA bytes":    swapAlg(t, good, "RS256"),
		"alg ES256 over EdDSA bytes":    swapAlg(t, good, "ES256"),
		"alg PS256 over EdDSA bytes":    swapAlg(t, good, "PS256"),
	}
	for name, token := range cases {
		t.Run(name, func(t *testing.T) {
			c, err := m.VerifyAccessToken(token)
			if c != nil {
				t.Fatalf("hostile token produced claims %+v", c)
			}
			if !hostiletest.IsInvalidOrMalformed(err) {
				t.Fatalf("VerifyAccessToken = %v, want ErrTokenInvalid or ErrTokenMalformed", err)
			}
		})
	}
}

// swapAlg re-encodes the header of token with another alg and keeps payload
// and signature, which is what an adversary does when the signature check is
// the only barrier left.
func swapAlg(t *testing.T, token, alg string) string {
	t.Helper()
	h := hostiletest.DecodeHeader(t, token)
	h["alg"] = alg
	return hostiletest.RebuildHeader(t, token, h)
}

// The same attack aimed at the refresh path: rotation must not turn an
// unsigned or foreign-algorithm token into a fresh pair.
func TestHostile_AlgConfusion_rotationRefusesForgedRefreshTokens(t *testing.T) {
	e := hostiletest.NewEnv(t)
	m := e.Module(t, jwt.Config{})
	forged := map[string]string{
		"alg none":        e.Sign(t, gjwt.SigningMethodNone, gjwt.UnsafeAllowNoneSignatureType, nil, hostiletest.ClaimsFor("refresh")),
		"HS256 by pub":    e.Sign(t, gjwt.SigningMethodHS256, []byte(e.Pub), nil, hostiletest.ClaimsFor("refresh")),
		"HS256 by secret": e.Sign(t, gjwt.SigningMethodHS256, e.Secret, nil, hostiletest.ClaimsFor("refresh")),
	}
	for name, token := range forged {
		t.Run(name, func(t *testing.T) {
			pair, err := m.RotateTokens(token, hostiletest.Extra{Role: "admin"})
			if pair != nil {
				t.Fatal("forged refresh token rotated into a pair")
			}
			if !hostiletest.IsInvalidOrMalformed(err) {
				t.Fatalf("RotateTokens = %v, want ErrTokenInvalid or ErrTokenMalformed", err)
			}
		})
	}
}

// A token signed by another Ed25519 key is refused even when it names this
// module's kid: the kid selects a key, it does not vouch for the signature.
func TestHostile_AlgConfusion_foreignEd25519KeyUnderOurKid(t *testing.T) {
	e := hostiletest.NewEnv(t)
	other := hostiletest.NewEnv(t)
	m := e.Module(t, jwt.Config{})
	token := e.Sign(t, gjwt.SigningMethodEdDSA, other.Priv, nil, hostiletest.ClaimsFor("access"))
	if _, err := m.VerifyAccessToken(token); !errors.Is(err, jwt.ErrTokenInvalid) {
		t.Fatalf("VerifyAccessToken = %v, want ErrTokenInvalid", err)
	}
}
