package hostile_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth"
)

// Attacker: someone who can put a string in the callback ("id_token") or a
// compromised provider that can sign garbage. Effect they want: a session as
// somebody else, or a token minted for another client/flow accepted here.

var jsonNull = json.RawMessage("null")

type tokCase struct {
	name   string
	jwks   func(t *testing.T) []byte // nil: the provider publishes keyA under testKID
	cfg    func(*oauth.Config)
	token  func(t *testing.T) string
	accept bool
	why    string // substring the refusal must contain, proving the right control fired
}

func stdJWKS(*testing.T) []byte {
	a, _ := rsaKeys()
	return jwksDoc(rsaJWK(testKID, &a.PublicKey, nil))
}

func signA(t *testing.T, c map[string]any) string {
	t.Helper()
	a, _ := rsaKeys()
	return mint{Key: a, Claims: c}.String(t)
}

func runTokCases(t *testing.T, cases []tokCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			jwks := stdJWKS
			if tc.jwks != nil {
				jwks = tc.jwks
			}
			srv := serve(t, staticBody(jwks(t)))
			c := oidcClient(t, srv.URL, tc.cfg)
			got, err := verify(t, c, tc.token(t))
			if tc.accept {
				if err != nil {
					t.Fatalf("control token refused: %v", err)
				}
				return
			}
			mustRejectToken(t, got, err)
			if tc.why != "" && !strings.Contains(err.Error(), tc.why) {
				t.Fatalf("refused for the wrong reason, want %q in: %v", tc.why, err)
			}
		})
	}
}

func TestHostile_IDToken_algorithmConfusion(t *testing.T) {
	a, b := rsaKeys()
	pkix, err := x509.MarshalPKIXPublicKey(&a.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pkcs1 := x509.MarshalPKCS1PublicKey(&a.PublicKey)
	pemKey := []byte("-----BEGIN PUBLIC KEY-----\n" + base64.StdEncoding.EncodeToString(pkix) + "\n-----END PUBLIC KEY-----\n")
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	good := claims(testNonce, nil)

	cases := []tokCase{
		{name: "control RS256", token: func(t *testing.T) string { return signA(t, good) }, accept: true},
		{name: "control PS256", token: func(t *testing.T) string { return mint{Alg: "PS256", Key: a, Claims: good}.String(t) }, accept: true},
		{name: "control RS512", token: func(t *testing.T) string { return mint{Alg: "RS512", Key: a, Claims: good}.String(t) }, accept: true},
	}
	for _, alg := range []string{"none", "None", "NONE", "nOnE"} {
		cases = append(cases, tokCase{name: "alg " + alg + " unsigned", why: "signing method", token: func(t *testing.T) string {
			return mint{Alg: alg, Claims: good}.String(t)
		}})
	}
	cases = append(cases, tokCase{name: "alg none with a forged signature segment", why: "signing method", token: func(t *testing.T) string {
		return mint{Alg: "none", Claims: good}.String(t) + "AAAA"
	}})
	secrets := map[string][]byte{
		"the PKIX DER":          pkix,
		"the PKCS1 DER":         pkcs1,
		"the PEM":               pemKey,
		"the modulus":           a.N.Bytes(),
		"an empty secret":       {},
		"the JWKS n, base64url": []byte(b64Int(a.N)),
	}
	for _, alg := range []string{"HS256", "HS384", "HS512"} {
		for what, secret := range secrets {
			cases = append(cases, tokCase{name: alg + " keyed with " + what, why: "signing method", token: func(t *testing.T) string {
				return mint{Alg: alg, HMAC: secret, Claims: good}.String(t)
			}})
		}
	}
	cases = append(cases,
		tokCase{name: "RS256 signed by another issuer's key", why: "crypto/rsa: verification error", token: func(t *testing.T) string {
			return mint{Key: b, Claims: good}.String(t)
		}},
		tokCase{name: "ES256 header over an RSA key", token: func(t *testing.T) string {
			return mint{Alg: "ES256", EC: ec, Claims: good}.String(t)
		}},
		tokCase{name: "header says RS256 but the signature is PSS", token: func(t *testing.T) string {
			return mint{Alg: "PS256", Key: a, Claims: good, Header: map[string]any{"alg": "RS256"}}.String(t)
		}},
		tokCase{name: "header says PS256 but the signature is PKCS1", token: func(t *testing.T) string {
			return mint{Alg: "RS256", Key: a, Claims: good, Header: map[string]any{"alg": "PS256"}}.String(t)
		}},
		tokCase{name: "alg is the empty string", why: "signing method", token: func(t *testing.T) string {
			return mint{Key: a, Claims: good, Header: map[string]any{"alg": ""}}.String(t)
		}},
		tokCase{name: "alg is absent", token: func(t *testing.T) string {
			return mint{Key: a, Claims: good, Header: map[string]any{"alg": nil}}.String(t)
		}},
		tokCase{name: "alg is a number", token: func(t *testing.T) string {
			return mint{Key: a, Claims: good, Header: map[string]any{"alg": 256}}.String(t)
		}},
		tokCase{name: "alg is an array", token: func(t *testing.T) string {
			return mint{Key: a, Claims: good, Header: map[string]any{"alg": []string{"RS256"}}}.String(t)
		}},
		tokCase{name: "alg is lowercase", why: "signing method", token: func(t *testing.T) string {
			return mint{Key: a, Claims: good, Header: map[string]any{"alg": "rs256"}}.String(t)
		}},
		tokCase{name: "alg has trailing space", why: "signing method", token: func(t *testing.T) string {
			return mint{Key: a, Claims: good, Header: map[string]any{"alg": "RS256 "}}.String(t)
		}},
	)
	runTokCases(t, cases)
}

func TestHostile_IDToken_embeddedKeyMaterialInHeader(t *testing.T) {
	a, b := rsaKeys()
	good := claims(testNonce, nil)
	attackerJWK := rsaJWK("evil", &b.PublicKey, nil)

	// A jku/x5u the verifier must never dereference.
	spy := serve(t, staticBody(jwksDoc(attackerJWK)))

	cases := []tokCase{
		{name: "embedded jwk, no kid", token: func(t *testing.T) string {
			return mint{Key: b, Kid: "-", Claims: good, Header: map[string]any{"jwk": attackerJWK}}.String(t)
		}},
		{name: "embedded jwk, legitimate kid", token: func(t *testing.T) string {
			return mint{Key: b, Claims: good, Header: map[string]any{"jwk": attackerJWK}}.String(t)
		}},
		{name: "embedded jwk, attacker kid", token: func(t *testing.T) string {
			return mint{Key: b, Kid: "evil", Claims: good, Header: map[string]any{"jwk": attackerJWK}}.String(t)
		}},
		{name: "x5c with an attacker certificate", token: func(t *testing.T) string {
			return mint{Key: b, Kid: "-", Claims: good, Header: map[string]any{"x5c": []string{base64.StdEncoding.EncodeToString([]byte("not-a-real-cert"))}}}.String(t)
		}},
		{name: "jku points at the attacker's JWKS", token: func(t *testing.T) string {
			return mint{Key: b, Kid: "evil", Claims: good, Header: map[string]any{"jku": spy.URL + "/jwks"}}.String(t)
		}},
		{name: "x5u points at the attacker's certificate", token: func(t *testing.T) string {
			return mint{Key: b, Kid: "evil", Claims: good, Header: map[string]any{"x5u": spy.URL + "/cert"}}.String(t)
		}},
		{name: "control: the same header members on a token signed by the real key", accept: true, token: func(t *testing.T) string {
			return mint{Key: a, Claims: good, Header: map[string]any{"jku": spy.URL + "/jwks", "x5u": spy.URL + "/cert"}}.String(t)
		}},
	}
	runTokCases(t, cases)

	// The point of jku/x5u is that the verifier fetches them. It must not.
	if n := spy.hits.Load(); n != 0 {
		t.Fatalf("the verifier fetched an attacker-supplied header URL %d time(s)", n)
	}
}

func TestHostile_IDToken_kidAttacks(t *testing.T) {
	a, b := rsaKeys()
	good := claims(testNonce, nil)
	twoKeys := func(*testing.T) []byte {
		return jwksDoc(rsaJWK(testKID, &a.PublicKey, nil), rsaJWK("k2", &b.PublicKey, nil))
	}
	anon := func(*testing.T) []byte { return jwksDoc(rsaJWK("", &a.PublicKey, nil)) }
	dupEnc := func(*testing.T) []byte {
		return jwksDoc(rsaJWK(testKID, &b.PublicKey, map[string]any{"use": "enc"}), rsaJWK(testKID, &a.PublicKey, nil))
	}
	dupSignOnly := func(*testing.T) []byte {
		return jwksDoc(rsaJWK(testKID, &b.PublicKey, map[string]any{"key_ops": []string{"sign"}}), rsaJWK(testKID, &a.PublicKey, nil))
	}
	dupPlain := func(*testing.T) []byte {
		return jwksDoc(rsaJWK(testKID, &b.PublicKey, nil), rsaJWK(testKID, &a.PublicKey, nil))
	}

	cases := []tokCase{
		{name: "control: known kid", jwks: twoKeys, accept: true, token: func(t *testing.T) string { return signA(t, good) }},
		{name: "control: no kid against a single kid-less key", jwks: anon, accept: true, token: func(t *testing.T) string {
			a, _ := rsaKeys()
			return mint{Key: a, Kid: "-", Claims: good}.String(t)
		}},
		{name: "kid absent among several keys", jwks: twoKeys, why: "unknown kid", token: func(t *testing.T) string {
			a, _ := rsaKeys()
			return mint{Key: a, Kid: "-", Claims: good}.String(t)
		}},
		{name: "kid absent, single key that has a kid", why: "unknown kid", token: func(t *testing.T) string {
			a, _ := rsaKeys()
			return mint{Key: a, Kid: "-", Claims: good}.String(t)
		}},
		{name: "kid named but the only key has none", jwks: anon, why: "unknown kid", token: func(t *testing.T) string { return signA(t, good) }},
		{name: "unknown kid", jwks: twoKeys, why: "unknown kid", token: func(t *testing.T) string {
			a, _ := rsaKeys()
			return mint{Key: a, Kid: "k3", Claims: good}.String(t)
		}},
		{name: "kid collision: the enc-only twin must not verify", jwks: dupEnc, token: func(t *testing.T) string {
			_, b := rsaKeys()
			return mint{Key: b, Claims: good}.String(t)
		}},
		{name: "control: kid collision, the sig key still verifies", jwks: dupEnc, accept: true, token: func(t *testing.T) string { return signA(t, good) }},
		{name: "kid collision: the sign-only twin must not verify", jwks: dupSignOnly, token: func(t *testing.T) string {
			_, b := rsaKeys()
			return mint{Key: b, Claims: good}.String(t)
		}},
		{name: "control: kid collision, key_ops sign twin is skipped", jwks: dupSignOnly, accept: true, token: func(t *testing.T) string { return signA(t, good) }},
		{name: "kid collision between two sig keys never falls through to a later key", jwks: dupPlain, token: func(t *testing.T) string { return signA(t, good) }},
	}
	// A kid of the wrong JSON type must not select a key by accident.
	for name, kid := range map[string]any{
		"number": 1, "array": []string{testKID}, "object": map[string]string{"kid": testKID},
		"bool": true, "null": jsonNull,
	} {
		cases = append(cases, tokCase{name: "kid is a " + name, jwks: twoKeys, token: func(t *testing.T) string {
			a, _ := rsaKeys()
			return mint{Key: a, Claims: good, Header: map[string]any{"kid": kid}}.String(t)
		}})
	}
	// Injected kids are just unknown kids.
	for name, kid := range map[string]string{
		"nul suffix": testKID + "\x00", "trailing space": testKID + " ", "uppercase": "K1",
		"path traversal": "../" + testKID, "zero-width suffix": "k1\u200b", "crlf": testKID + "\r\nX: y",
		"empty": "",
	} {
		cases = append(cases, tokCase{name: "kid " + name, jwks: twoKeys, token: func(t *testing.T) string {
			a, _ := rsaKeys()
			return mint{Key: a, Claims: good, Header: map[string]any{"kid": kid}}.String(t)
		}})
	}
	runTokCases(t, cases)
}
