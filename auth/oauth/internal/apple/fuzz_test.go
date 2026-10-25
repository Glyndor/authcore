package apple_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth/internal/apple"
)

var errFuzzApple = errors.New("oauth: invalid configuration")

// FuzzClientSecret feeds the Apple client-secret builder arbitrary
// identifiers and key bytes. The property: no panic, every refusal wraps the
// config sentinel, and a builder that is returned was given ten-character
// [A-Z0-9] identifiers, a non-empty client id without surrounding whitespace
// and a key an independent PEM/PKCS#8 parse also accepts, and its secret
// verifies under that key.
func FuzzClientSecret(f *testing.F) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		f.Fatal(err)
	}
	good := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	f.Add(good, "ABCDE12345", "KEYID67890", "com.example.services")
	f.Add(append([]byte("junk\n"), good...), "ABCDE12345", "KEYID67890", "com.example.services")
	f.Add(append(append([]byte(nil), good...), good...), "ABCDE12345", "KEYID67890", "com.example.services")
	f.Add(good, "abcde12345", "KEYID67890", "com.example.services")
	f.Add(good, "ABCDE1234", "KEYID67890", "com.example.services")
	f.Add(good, "ABCDE12345", "KEYID678901", "com.example.services")
	f.Add(good, "ABCDE12345", "KEYID67890", "com.example.services\n")
	f.Add(good, "ABCDE12345", "KEYID67890", " x")
	f.Add(good[:len(good)/2], "ABCDE12345", "KEYID67890", "x")
	f.Add([]byte{}, "", "", "")

	f.Fuzz(func(t *testing.T, p8 []byte, team, keyID, client string) {
		sign, err := apple.ClientSecret(errFuzzApple, team, keyID, client, p8)
		if err != nil {
			if !errors.Is(err, errFuzzApple) {
				t.Fatalf("a refusal that does not wrap the config sentinel: %v", err)
			}
			return
		}
		for _, id := range []string{team, keyID} {
			if len(id) != 10 || strings.Trim(id, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") != "" {
				t.Fatalf("accepted the identifier %q", id)
			}
		}
		if client == "" || strings.TrimSpace(client) != client {
			t.Fatalf("accepted the client id %q", client)
		}
		block, _ := pem.Decode(p8)
		if block == nil || block.Type != "PRIVATE KEY" {
			t.Fatal("accepted key bytes that carry no PRIVATE KEY block")
		}
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		ec, ok := parsed.(*ecdsa.PrivateKey)
		if err != nil || !ok || ec.Curve != elliptic.P256() {
			t.Fatalf("accepted a key that is not a P-256 PKCS#8 key: %v %T", err, parsed)
		}
		secret, err := sign(context.Background())
		if err != nil {
			t.Fatalf("a builder that was returned could not sign: %v", err)
		}
		parts := strings.Split(secret, ".")
		sig, derr := base64.RawURLEncoding.DecodeString(parts[len(parts)-1])
		if len(parts) != 3 || derr != nil || len(sig) != 64 {
			t.Fatalf("malformed secret %q", secret)
		}
		sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		if !ecdsa.Verify(&ec.PublicKey, sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
			t.Fatal("the secret does not verify under the configured key")
		}
	})
}
