package hostile_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth"
)

func TestHostile_IDToken_jwkRestrictions(t *testing.T) {
	a, b := rsaKeys()
	good := claims(testNonce, nil)
	with := func(extra map[string]any) func(*testing.T) []byte {
		return func(*testing.T) []byte { return jwksDoc(rsaJWK(testKID, &a.PublicKey, extra)) }
	}
	tok := func(t *testing.T) string { return signA(t, good) }

	small1024, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	small2047, err := rsa.GenerateKey(rand.Reader, 2047)
	if err != nil {
		t.Fatal(err)
	}
	huge := new(big.Int).Lsh(big.NewInt(1), 16400)
	huge.Add(huge, big.NewInt(1))

	cases := []tokCase{
		{name: "control: use sig", jwks: with(map[string]any{"use": "sig"}), token: tok, accept: true},
		{name: "control: key_ops verify", jwks: with(map[string]any{"key_ops": []string{"verify"}}), token: tok, accept: true},
		{name: "control: key_ops verify and encrypt", jwks: with(map[string]any{"key_ops": []string{"verify", "encrypt"}}), token: tok, accept: true},
		{name: "control: alg pinned to RS256", jwks: with(map[string]any{"alg": "RS256"}), token: tok, accept: true},
		{name: "use enc", jwks: with(map[string]any{"use": "enc"}), token: tok},
		{name: "use Sig (wrong case)", jwks: with(map[string]any{"use": "Sig"}), token: tok},
		{name: "key_ops encrypt only", jwks: with(map[string]any{"key_ops": []string{"encrypt"}}), token: tok},
		{name: "key_ops sign only", jwks: with(map[string]any{"key_ops": []string{"sign"}}), token: tok},
		{name: "key_ops VERIFY (wrong case)", jwks: with(map[string]any{"key_ops": []string{"VERIFY"}}), token: tok},
		{name: "alg pinned to RS512 but token is RS256", jwks: with(map[string]any{"alg": "RS512"}), token: tok},
		{name: "alg pinned to PS256 but token is RS256", jwks: with(map[string]any{"alg": "PS256"}), token: tok},
		{name: "alg pinned to HS256", jwks: with(map[string]any{"alg": "HS256"}), token: tok},
		{name: "alg pinned to none", jwks: with(map[string]any{"alg": "none"}), token: tok},
		{name: "RSA 1024-bit key signed the token", jwks: func(*testing.T) []byte {
			return jwksDoc(rsaJWK(testKID, &small1024.PublicKey, nil))
		}, token: func(t *testing.T) string { return mint{Key: small1024, Claims: good}.String(t) }},
		{name: "RSA 2047-bit key signed the token", jwks: func(*testing.T) []byte {
			return jwksDoc(rsaJWK(testKID, &small2047.PublicKey, nil))
		}, token: func(t *testing.T) string { return mint{Key: small2047, Claims: good}.String(t) }},
		{name: "control: the small key is skipped but a sound sibling still works", accept: true, jwks: func(*testing.T) []byte {
			return jwksDoc(rsaJWK("small", &small1024.PublicKey, nil), rsaJWK("k1", &a.PublicKey, nil))
		}, token: tok},
		{name: "RSA exponent 1", jwks: func(*testing.T) []byte {
			k := rsaJWK(testKID, &a.PublicKey, nil)
			k["e"] = b64([]byte{1})
			return jwksDoc(k)
		}, token: tok},
		{name: "RSA exponent 0", jwks: func(*testing.T) []byte {
			k := rsaJWK(testKID, &a.PublicKey, nil)
			k["e"] = b64([]byte{0})
			return jwksDoc(k)
		}, token: tok},
		{name: "RSA exponent wider than 31 bits", jwks: func(*testing.T) []byte {
			k := rsaJWK(testKID, &a.PublicKey, nil)
			k["e"] = b64([]byte{1, 0, 0, 0, 1})
			return jwksDoc(k)
		}, token: tok},
		{name: "RSA modulus above 16384 bits is skipped, sibling works", accept: true, jwks: func(*testing.T) []byte {
			big := map[string]any{"kty": "RSA", "kid": "huge", "n": b64Int(huge), "e": "AQAB"}
			return jwksDoc(big, rsaJWK("k1", &a.PublicKey, nil))
		}, token: tok},
		{name: "RSA modulus above 16384 bits cannot be the signer", jwks: func(*testing.T) []byte {
			return jwksDoc(map[string]any{"kty": "RSA", "kid": testKID, "n": b64Int(huge), "e": "AQAB"})
		}, token: tok},
		{name: "RSA key with n and e missing", jwks: func(*testing.T) []byte {
			return jwksDoc(map[string]any{"kty": "RSA", "kid": testKID})
		}, token: tok},
		{name: "JWKS key signed by the attacker's key only", jwks: func(*testing.T) []byte {
			return jwksDoc(rsaJWK(testKID, &b.PublicKey, nil))
		}, token: tok},
	}

	// A key the parser must skip may sit first under the same kid. If it were
	// kept it would be picked before the real key and the real token would
	// stop verifying, so "the sound key still verifies" shows the skip.
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	offCurve := ecJWK(testKID, "P-256", &p256.PublicKey, nil)
	offCurve["y"] = b64(make([]byte, 32))
	wrongCurve := ecJWK(testKID, "P-256", &p256.PublicKey, nil)
	wrongCurve["crv"] = "secp256k1"
	e1 := rsaJWK(testKID, &a.PublicKey, nil)
	e1["e"] = b64([]byte{1})
	noKty := rsaJWK(testKID, &a.PublicKey, nil)
	delete(noKty, "kty")
	lowerKty := rsaJWK(testKID, &a.PublicKey, nil)
	lowerKty["kty"] = "rsa"
	for name, bad := range map[string]map[string]any{
		"a modulus above 16384 bits":    {"kty": "RSA", "kid": testKID, "n": b64Int(huge), "e": "AQAB"},
		"a 1024-bit modulus":            rsaJWK(testKID, &small1024.PublicKey, nil),
		"an exponent of 1":              e1,
		"an EC point off the curve":     offCurve,
		"an EC key on an unknown curve": wrongCurve,
		"an oct key":                    {"kty": "oct", "kid": testKID, "k": b64([]byte("secret"))},
		"an OKP key":                    {"kty": "OKP", "crv": "Ed25519", "kid": testKID, "x": b64(make([]byte, 32))},
		"a key with no kty":             noKty,
		"a lower-case kty":              lowerKty,
		"a key for encryption":          rsaJWK(testKID, &b.PublicKey, map[string]any{"use": "enc"}),
		"a key limited to signing":      rsaJWK(testKID, &b.PublicKey, map[string]any{"key_ops": []string{"sign"}}),
	} {
		cases = append(cases, tokCase{
			name: "control: the sound key still verifies next to " + name, accept: true, token: tok,
			jwks: func(*testing.T) []byte { return jwksDoc(bad, rsaJWK(testKID, &a.PublicKey, nil)) },
		})
	}
	runTokCases(t, cases)
}

// Microsoft-style multi-tenant setups rely on the JWK "issuer" member to keep
// a key from signing for a tenant it does not belong to.
func TestHostile_IDToken_keyIssuerRestriction(t *testing.T) {
	a, _ := rsaKeys()
	const (
		t1 = "11111111-1111-1111-1111-111111111111"
		t2 = "22222222-2222-2222-2222-222222222222"
	)
	iss := func(tenant string) string { return "https://login.microsoftonline.com/" + tenant + "/v2.0" }
	multi := func(c *oauth.Config) {
		c.Provider.Issuer = iss("common-placeholder")
		c.IssuerValidator = oauth.AzureMultiTenantIssuer()
	}
	pinned := func(tenant string) func(*testing.T) []byte {
		return func(*testing.T) []byte {
			return jwksDoc(rsaJWK(testKID, &a.PublicKey, map[string]any{"issuer": iss(tenant)}))
		}
	}
	template := func(*testing.T) []byte {
		return jwksDoc(rsaJWK(testKID, &a.PublicKey, map[string]any{"issuer": "https://login.microsoftonline.com/{tenantid}/v2.0"}))
	}
	tokenFor := func(over map[string]any) func(*testing.T) string {
		return func(t *testing.T) string { return signA(t, claims(testNonce, over)) }
	}
	runTokCases(t, []tokCase{
		{name: "control: key pinned to tenant 1, token from tenant 1", cfg: multi, jwks: pinned(t1), accept: true, token: tokenFor(map[string]any{"iss": iss(t1)})},
		{name: "control: template key, tid matches iss", cfg: multi, jwks: template, accept: true, token: tokenFor(map[string]any{"iss": iss(t2), "tid": t2})},
		{name: "key pinned to tenant 1 signs for tenant 2", cfg: multi, jwks: pinned(t1), why: "restricted", token: tokenFor(map[string]any{"iss": iss(t2)})},
		{name: "template key, token has no tid", cfg: multi, jwks: template, why: "no tid", token: tokenFor(map[string]any{"iss": iss(t2)})},
		{name: "template key, tid disagrees with iss", cfg: multi, jwks: template, why: "restricted", token: tokenFor(map[string]any{"iss": iss(t2), "tid": t1})},
		{name: "template key, tid is a number", cfg: multi, jwks: template, why: "no tid", token: tokenFor(map[string]any{"iss": iss(t2), "tid": 22})},
		{name: "template key, tid tries to inject a path", cfg: multi, jwks: template, token: tokenFor(map[string]any{"iss": iss(t2), "tid": t2 + "/../" + t1})},
		{name: "multi-tenant validator refuses a look-alike host", cfg: multi, why: "rejected", token: tokenFor(map[string]any{"iss": "https://login.microsoftonline.com.evil.example/" + t1 + "/v2.0"})},
		{name: "multi-tenant validator refuses a non-GUID tenant", cfg: multi, why: "rejected", token: tokenFor(map[string]any{"iss": iss("common")})},
		{name: "multi-tenant validator refuses a trailing newline", cfg: multi, why: "rejected", token: tokenFor(map[string]any{"iss": iss(t1) + "\n"})},
		{name: "multi-tenant validator refuses a v1.0 issuer", cfg: multi, why: "rejected", token: tokenFor(map[string]any{"iss": "https://login.microsoftonline.com/" + t1 + "/"})},
	})
}
