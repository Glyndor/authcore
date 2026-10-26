package hostiletest

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"sync"
)

// Keys are generated once: RSA generation dominates the cost of a test.
var (
	keyOnce sync.Once
	keyA    *rsa.PrivateKey // the provider's signing key
	keyB    *rsa.PrivateKey // some other issuer's key
)

// RSAKeys returns the two RSA keys shared by every test.
func RSAKeys() (*rsa.PrivateKey, *rsa.PrivateKey) {
	keyOnce.Do(func() {
		var err error
		if keyA, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic(err)
		}
		if keyB, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic(err)
		}
	})
	return keyA, keyB
}

// B64 is the unpadded base64url encoding JWS uses.
func B64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// B64Int encodes n as a JWK big-endian integer.
func B64Int(n *big.Int) string { return B64(n.Bytes()) }

// RSAJWK returns the JWK of pub with extra members merged in.
func RSAJWK(kid string, pub *rsa.PublicKey, extra map[string]any) map[string]any {
	k := map[string]any{
		"kty": "RSA", "n": B64Int(pub.N), "e": B64Int(big.NewInt(int64(pub.E))),
	}
	if kid != "" {
		k["kid"] = kid
	}
	for name, v := range extra {
		k[name] = v
	}
	return k
}

// ECJWK returns the JWK of pub with extra members merged in.
func ECJWK(kid, crv string, pub *ecdsa.PublicKey, extra map[string]any) map[string]any {
	size := (pub.Curve.Params().BitSize + 7) / 8
	point, err := pub.Bytes() // 0x04 || X || Y
	if err != nil {
		panic(err)
	}
	k := map[string]any{
		"kty": "EC", "crv": crv,
		"x": B64(point[1 : 1+size]),
		"y": B64(point[1+size:]),
	}
	if kid != "" {
		k["kid"] = kid
	}
	for name, v := range extra {
		k[name] = v
	}
	return k
}

// JWKSDoc renders a JWKS document holding keys.
func JWKSDoc(keys ...map[string]any) []byte {
	out, err := json.Marshal(map[string]any{"keys": keys})
	if err != nil {
		panic(err)
	}
	return out
}
