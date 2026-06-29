package keymanager_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager"
)

// FuzzFromPEM drives the PEM key-material decoder with arbitrary bytes. FromPEM
// turns untrusted-looking input (PEM blocks sourced from env/secret stores)
// into key structures, so it must never panic — only return a manager or an
// error.
func FuzzFromPEM(f *testing.F) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatalf("seed key: %v", err)
	}
	privDER, _ := x509.MarshalPKCS8PrivateKey(priv)
	pubDER, _ := x509.MarshalPKIXPublicKey(pub)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	secret := make([]byte, 32)

	f.Add(privPEM, pubPEM, secret)                          // valid set
	f.Add([]byte("not a pem"), []byte("not a pem"), secret) // garbage
	f.Add(privPEM, pubPEM, []byte("short"))                 // bad secret length
	f.Add([]byte{}, []byte{}, []byte{})                     // empty

	f.Fuzz(func(t *testing.T, privBytes, pubBytes, secretBytes []byte) {
		km, err := keymanager.FromPEM(privBytes, pubBytes, secretBytes)
		if err == nil && km == nil {
			t.Fatal("FromPEM returned a nil manager with a nil error")
		}
		if err != nil && km != nil {
			t.Fatal("FromPEM returned a manager alongside an error")
		}
	})
}
