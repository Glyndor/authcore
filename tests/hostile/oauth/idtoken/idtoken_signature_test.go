package idtoken_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/tests/hostile/oauth/hostiletest"
)

func TestHostile_IDToken_signatureAndEncoding(t *testing.T) {
	a, _ := hostiletest.RSAKeys()
	good := hostiletest.Claims(hostiletest.Nonce, nil)
	tok := hostiletest.SignA(t, good)
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("test token has %d parts", len(parts))
	}
	other := hostiletest.SignA(t, hostiletest.Claims(hostiletest.Nonce, map[string]any{"sub": "someone-else"}))
	otherParts := strings.Split(other, ".")

	flip := func(s string) string {
		last := s[len(s)-1]
		repl := byte('A')
		if last == 'A' {
			repl = 'B'
		}
		return s[:len(s)-1] + string(repl)
	}
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	longSig := hostiletest.B64(append([]byte{0}, sigBytes...))

	cases := []tokCase{
		{name: "control: the canonical token", token: func(*testing.T) string { return tok }, accept: true},
		{name: "last signature character flipped", token: func(*testing.T) string { return parts[0] + "." + parts[1] + "." + flip(parts[2]) }},
		{name: "signature truncated", token: func(*testing.T) string { return parts[0] + "." + parts[1] + "." + parts[2][:len(parts[2])-8] }},
		{name: "signature with a leading zero byte", token: func(*testing.T) string { return parts[0] + "." + parts[1] + "." + longSig }},
		{name: "signature removed, dot kept", token: func(*testing.T) string { return parts[0] + "." + parts[1] + "." }},
		{name: "signature segment removed", token: func(*testing.T) string { return parts[0] + "." + parts[1] }},
		{name: "payload swapped for another signed payload", token: func(*testing.T) string { return parts[0] + "." + otherParts[1] + "." + parts[2] }},
		{name: "header swapped, signature kept", token: func(*testing.T) string {
			h := hostiletest.B64([]byte(`{"alg":"RS256","kid":"k1","x":1}`))
			return h + "." + parts[1] + "." + parts[2]
		}},
		{name: "four segments", token: func(*testing.T) string { return tok + ".AAAA" }},
		{name: "leading dot", token: func(*testing.T) string { return "." + tok }},
		{name: "trailing dot", token: func(*testing.T) string { return tok + "." }},
		{name: "Bearer prefix", token: func(*testing.T) string { return "Bearer " + tok }},
		{name: "leading space", token: func(*testing.T) string { return " " + tok }},
		{name: "trailing newline", token: func(*testing.T) string { return tok + "\n" }},
		{name: "newline inside the signature", token: func(*testing.T) string {
			return parts[0] + "." + parts[1] + "." + parts[2][:40] + "\n" + parts[2][40:]
		}},
		{name: "carriage return inside the payload", token: func(*testing.T) string {
			return parts[0] + "." + parts[1][:10] + "\r" + parts[1][10:] + "." + parts[2]
		}},
		{name: "padded base64 signature", token: func(*testing.T) string { return tok + "==" }},
		{name: "standard-alphabet characters", token: func(*testing.T) string { return strings.ReplaceAll(tok, "_", "/") + "+" }},
		{name: "empty token", token: func(*testing.T) string { return "" }},
		{name: "dots only", token: func(*testing.T) string { return ".." }},
		{name: "plain garbage", token: func(*testing.T) string { return "not-a-jwt" }},
		{name: "NUL byte in the token", token: func(*testing.T) string { return tok + "\x00" }},
		{name: "non-ASCII byte in the token", token: func(*testing.T) string { return parts[0] + "." + parts[1] + "é." + parts[2] }},
	}
	// A second spelling of the same signed token must not verify: callers
	// that blocklist or deduplicate by string would see two tokens.
	spellings := 0
	for i := range 3 {
		seg := parts[i]
		if len(seg)%4 == 0 || len(seg)%4 == 1 {
			continue // no unused bits to play with
		}
		alt := altSpelling(seg)
		dec1, _ := base64.RawURLEncoding.DecodeString(seg)
		dec2, err := base64.RawURLEncoding.DecodeString(alt)
		if err != nil || string(dec1) != string(dec2) {
			t.Fatalf("segment %d: test bug, the alternative spelling decodes differently", i)
		}
		spellings++
		p := append([]string(nil), parts...)
		p[i] = alt
		cases = append(cases, tokCase{name: fmt.Sprintf("non-canonical base64 in segment %d", i), why: "base64", token: func(*testing.T) string { return strings.Join(p, ".") }})
	}
	if spellings == 0 {
		t.Fatal("no segment of the test token has unused base64 bits: the second-spelling attack was not exercised")
	}
	_ = a
	runTokCases(t, cases)
}

func altSpelling(seg string) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := strings.IndexByte(alphabet, seg[len(seg)-1])
	return seg[:len(seg)-1] + string(alphabet[last^1])
}

func TestHostile_IDToken_ecdsa(t *testing.T) {
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	good := hostiletest.Claims(hostiletest.Nonce, nil)
	jwksOf := func(crv string, k *ecdsa.PrivateKey, extra map[string]any) func(*testing.T) []byte {
		return func(*testing.T) []byte {
			return hostiletest.JWKSDoc(hostiletest.ECJWK(hostiletest.KID, crv, &k.PublicKey, extra))
		}
	}
	tok := func(alg string, k *ecdsa.PrivateKey) func(*testing.T) string {
		return func(t *testing.T) string { return hostiletest.Mint{Alg: alg, EC: k, Claims: good}.String(t) }
	}
	runTokCases(t, []tokCase{
		{name: "control ES256", jwks: jwksOf("P-256", p256, nil), token: tok("ES256", p256), accept: true},
		{name: "control ES384", jwks: jwksOf("P-384", p384, nil), token: tok("ES384", p384), accept: true},
		{name: "control ES512", jwks: jwksOf("P-521", p521, nil), token: tok("ES512", p521), accept: true},
		{name: "ES384 token against a P-256 key", jwks: jwksOf("P-256", p256, nil), token: tok("ES384", p256)},
		{name: "ES256 token against a P-384 key", jwks: jwksOf("P-384", p384, nil), token: tok("ES256", p384)},
		{name: "ES256 token signed by a different P-256 key", jwks: jwksOf("P-256", p256, nil), token: tok("ES256", mustEC(t, elliptic.P256()))},
		{name: "JWK lies about the curve: P-384 point labelled P-256", jwks: jwksOf("P-256", p384, nil), token: tok("ES256", p384)},
		{name: "JWK on an unsupported curve", jwks: func(*testing.T) []byte {
			k := hostiletest.ECJWK(hostiletest.KID, "P-256", &p256.PublicKey, nil)
			k["crv"] = "secp256k1"
			return hostiletest.JWKSDoc(k)
		}, token: tok("ES256", p256)},
		{name: "JWK point is not on the curve", jwks: func(*testing.T) []byte {
			k := hostiletest.ECJWK(hostiletest.KID, "P-256", &p256.PublicKey, nil)
			k["y"] = hostiletest.B64(make([]byte, 32))
			return hostiletest.JWKSDoc(k)
		}, token: tok("ES256", p256)},
		{name: "JWK coordinates wider than the field", jwks: func(*testing.T) []byte {
			k := hostiletest.ECJWK(hostiletest.KID, "P-256", &p256.PublicKey, nil)
			k["x"] = hostiletest.B64(make([]byte, 4096))
			return hostiletest.JWKSDoc(k)
		}, token: tok("ES256", p256)},
		{name: "JWK is an oct (symmetric) key and the token is HS256", jwks: func(*testing.T) []byte {
			return hostiletest.JWKSDoc(map[string]any{"kty": "oct", "kid": hostiletest.KID, "k": hostiletest.B64([]byte("secret"))})
		}, token: func(t *testing.T) string {
			return hostiletest.Mint{Alg: "HS256", HMAC: []byte("secret"), Claims: good}.String(t)
		}},
		{name: "JWK is an unsupported OKP key", jwks: func(*testing.T) []byte {
			return hostiletest.JWKSDoc(map[string]any{"kty": "OKP", "crv": "Ed25519", "kid": hostiletest.KID, "x": hostiletest.B64(make([]byte, 32))})
		}, token: tok("ES256", p256)},
	})
}

func mustEC(t *testing.T, c elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}
