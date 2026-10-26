package jwk_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"math/big"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth/internal/jwks/jwk"
)

func enc(i *big.Int) string { return base64.RawURLEncoding.EncodeToString(i.Bytes()) }

// bits returns an integer whose bit length is exactly n.
func bits(n uint) *big.Int { return new(big.Int).Lsh(big.NewInt(1), n-1) }

func TestParseRSABoundaries(t *testing.T) {
	cases := []struct {
		name string
		n, e *big.Int
		ok   bool
	}{
		{"modulus at the 2048 floor", bits(2048), big.NewInt(65537), true},
		{"modulus below the floor", bits(2047), big.NewInt(65537), false},
		{"modulus at the 16384 ceiling", bits(16384), big.NewInt(65537), true},
		{"modulus above the ceiling", bits(16385), big.NewInt(65537), false},
		{"exponent 2", bits(2048), big.NewInt(2), true},
		{"exponent 1", bits(2048), big.NewInt(1), false},
		{"exponent 0", bits(2048), big.NewInt(0), false},
		{"exponent of 31 bits", bits(2048), new(big.Int).SetUint64(1<<31 - 1), true},
		{"exponent of 32 bits", bits(2048), new(big.Int).SetUint64(1 << 31), false},
		{"exponent wider than 64 bits", bits(2048), bits(80), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := jwk.Parse(jwk.JWK{Kty: "RSA", N: enc(c.n), E: enc(c.e)})
			if (err == nil) != c.ok {
				t.Fatalf("accepted=%v, want %v (err=%v)", err == nil, c.ok, err)
			}
		})
	}
}

func TestParseRefusesUndecodableMembers(t *testing.T) {
	good := enc(bits(2048))
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	x, y := enc(ec.X), enc(ec.Y)
	cases := map[string]jwk.JWK{
		"rsa modulus":                        {Kty: "RSA", N: "!!", E: "AQAB"},
		"rsa exponent":                       {Kty: "RSA", N: good, E: "!!"},
		"rsa exponent with trailing garbage": {Kty: "RSA", N: good, E: "AQAB!"},
		"rsa modulus with trailing garbage":  {Kty: "RSA", N: enc(bits(2100)) + "!", E: "AQAB"},
		"ec x":                               {Kty: "EC", Crv: "P-256", X: "!!", Y: y},
		"ec y":                               {Kty: "EC", Crv: "P-256", X: x, Y: "!!"},
	}
	for name, k := range cases {
		t.Run(name, func(t *testing.T) {
			pub, err := jwk.Parse(k)
			if err == nil || pub != nil {
				t.Fatalf("an undecodable %s must be refused, got key=%v err=%v", name, pub, err)
			}
		})
	}
	if _, err := jwk.Parse(jwk.JWK{Kty: "EC", Crv: "P-256", X: x, Y: y}); err != nil {
		t.Fatalf("the control key must parse: %v", err)
	}
}
