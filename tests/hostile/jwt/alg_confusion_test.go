package jwt_test

import (
	"errors"
	"testing"

	gjwt "github.com/golang-jwt/jwt/v5"

	"github.com/Glyndor/authcore/auth/jwt"
)

// isInvalidOrMalformed reports the two sentinels a hostile token may fail
// with. Anything else, nil included, means it got further than it should.
func isInvalidOrMalformed(err error) bool {
	return errors.Is(err, jwt.ErrTokenInvalid) || errors.Is(err, jwt.ErrTokenMalformed)
}

// An adversary who knows the algorithm list tries to choose it. The verifier
// accepts EdDSA and nothing else, whatever the header says.
func TestHostile_AlgConfusion_unsignedAndForeignAlgorithms(t *testing.T) {
	e := newEnv(t)
	m := e.module(t, jwt.Config{})

	good := e.signEdDSA(t, nil, claimsFor("access"))
	if _, err := m.VerifyAccessToken(good); err != nil {
		t.Fatalf("control token refused: %v", err)
	}

	hdr := func(alg string) string { return b64(`{"alg":` + alg + `,"kid":"` + e.kid + `"}`) }
	body := b64(`{"type":"access"}`)
	none := gjwt.UnsafeAllowNoneSignatureType

	cases := map[string]string{
		"alg none":                      e.sign(t, gjwt.SigningMethodNone, none, nil, claimsFor("access")),
		"alg none, bare dot":            hdr(`"none"`) + "." + body + ".",
		"alg None casing":               hdr(`"None"`) + "." + body + ".",
		"HS256 keyed by pub key":        e.sign(t, gjwt.SigningMethodHS256, []byte(e.pub), nil, claimsFor("access")),
		"HS256 keyed by the seed":       e.sign(t, gjwt.SigningMethodHS256, e.priv.Seed(), nil, claimsFor("access")),
		"HS256 keyed by refresh secret": e.sign(t, gjwt.SigningMethodHS256, e.secret, nil, claimsFor("access")),
		"HS512 keyed by pub key":        e.sign(t, gjwt.SigningMethodHS512, []byte(e.pub), nil, claimsFor("access")),
		"EdDSA header, empty signature": hdr(`"EdDSA"`) + "." + body + ".",
		"alg eddsa lowercase":           hdr(`"eddsa"`) + "." + body + ".AAAA",
		"alg empty":                     hdr(`""`) + "." + body + ".AAAA",
		"alg array":                     hdr(`["EdDSA"]`) + "." + body + ".AAAA",
		"alg number":                    hdr(`1`) + "." + body + ".AAAA",
		"alg missing":                   b64(`{"kid":"`+e.kid+`"}`) + "." + body + ".AAAA",
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
			if !isInvalidOrMalformed(err) {
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
	h := decodeHeader(t, token)
	h["alg"] = alg
	return rebuildHeader(t, token, h)
}

// The same attack aimed at the refresh path: rotation must not turn an
// unsigned or foreign-algorithm token into a fresh pair.
func TestHostile_AlgConfusion_rotationRefusesForgedRefreshTokens(t *testing.T) {
	e := newEnv(t)
	m := e.module(t, jwt.Config{})
	forged := map[string]string{
		"alg none":        e.sign(t, gjwt.SigningMethodNone, gjwt.UnsafeAllowNoneSignatureType, nil, claimsFor("refresh")),
		"HS256 by pub":    e.sign(t, gjwt.SigningMethodHS256, []byte(e.pub), nil, claimsFor("refresh")),
		"HS256 by secret": e.sign(t, gjwt.SigningMethodHS256, e.secret, nil, claimsFor("refresh")),
	}
	for name, token := range forged {
		t.Run(name, func(t *testing.T) {
			pair, err := m.RotateTokens(token, extra{Role: "admin"})
			if pair != nil {
				t.Fatal("forged refresh token rotated into a pair")
			}
			if !isInvalidOrMalformed(err) {
				t.Fatalf("RotateTokens = %v, want ErrTokenInvalid or ErrTokenMalformed", err)
			}
		})
	}
}

// A token signed by another Ed25519 key is refused even when it names this
// module's kid: the kid selects a key, it does not vouch for the signature.
func TestHostile_AlgConfusion_foreignEd25519KeyUnderOurKid(t *testing.T) {
	e := newEnv(t)
	other := newEnv(t)
	m := e.module(t, jwt.Config{})
	token := e.sign(t, gjwt.SigningMethodEdDSA, other.priv, nil, claimsFor("access"))
	if _, err := m.VerifyAccessToken(token); !errors.Is(err, jwt.ErrTokenInvalid) {
		t.Fatalf("VerifyAccessToken = %v, want ErrTokenInvalid", err)
	}
}
