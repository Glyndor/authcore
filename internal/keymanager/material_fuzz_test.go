package keymanager_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager"
)

// fixedMaterial returns a valid key set derived from fixed labels, so the
// positive seeds do not change between runs.
func fixedMaterial() (privPEM, pubPEM, secret []byte) {
	seed := sha256.Sum256([]byte("authcore fuzz signing seed"))
	priv := ed25519.NewKeyFromSeed(seed[:])
	privDER, _ := x509.MarshalPKCS8PrivateKey(priv)
	pubDER, _ := x509.MarshalPKIXPublicKey(priv.Public())
	sum := sha256.Sum256([]byte("authcore fuzz refresh secret"))
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), sum[:]
}

// FuzzFromPEM drives the PEM key-material decoder with arbitrary bytes. FromPEM
// turns untrusted-looking input (PEM blocks sourced from env/secret stores)
// into key structures, so it must never panic. Its verdict must also match a
// standard-library decoding plus the material contract, in both directions, and
// an accepted set must hold exactly the decoded keys and secret.
func FuzzFromPEM(f *testing.F) {
	privPEM, pubPEM, secret := fixedMaterial()
	spaced := append([]byte("\n  "), privPEM...)

	f.Add(privPEM, pubPEM, secret)                          // valid set
	f.Add(spaced, append(pubPEM, '\n', ' '), secret)        // valid set, surrounded by whitespace
	f.Add([]byte("not a pem"), []byte("not a pem"), secret) // garbage
	f.Add(privPEM, pubPEM, []byte("short"))                 // bad secret length
	f.Add(privPEM, pubPEM, make([]byte, 32))                // degenerate secret
	f.Add(pubPEM, privPEM, secret)                          // halves swapped
	f.Add([]byte{}, []byte{}, []byte{})                     // empty

	f.Fuzz(func(t *testing.T, privBytes, pubBytes, secretBytes []byte) {
		// The engine reuses seed slices across runs, so the wipe below must
		// act on a copy.
		secretBytes = bytes.Clone(secretBytes)
		wantPriv, wantPub, want := referenceKeys(privBytes, pubBytes, secretBytes)
		wantSecret := bytes.Clone(secretBytes)
		km, err := keymanager.FromPEM(privBytes, pubBytes, secretBytes)
		if err == nil && km == nil {
			t.Fatal("FromPEM returned a nil manager with a nil error")
		}
		if err != nil && km != nil {
			t.Fatal("FromPEM returned a manager alongside an error")
		}
		if (err == nil) != want {
			t.Fatalf("accepted=%v, reference says %v (err=%v)", err == nil, want, err)
		}
		if err != nil {
			return
		}
		if !bytes.Equal(km.PrivateKey(), wantPriv) || !bytes.Equal(km.PublicKey(), wantPub) || !bytes.Equal(km.RefreshSecret(), wantSecret) {
			t.Fatal("the manager holds other material than the input decoded to")
		}
		// The manager keeps its own copy of what the caller passed.
		clear(secretBytes)
		if !bytes.Equal(km.RefreshSecret(), wantSecret) {
			t.Fatal("wiping the caller's secret changed the manager's")
		}
		sig := ed25519.Sign(km.PrivateKey(), []byte("probe"))
		if !ed25519.Verify(wantPub, []byte("probe"), sig) {
			t.Fatal("the accepted private key does not sign for the public key")
		}
	})
}
