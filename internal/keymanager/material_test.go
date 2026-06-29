package keymanager_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager"
)

func genPair(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	return priv, pub
}

func TestFromKeys_valid(t *testing.T) {
	priv, pub := genPair(t)
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)

	km, err := keymanager.FromKeys(priv, pub, secret)
	if err != nil {
		t.Fatalf("FromKeys: %v", err)
	}
	if km.KeyID() == "" {
		t.Error("KeyID not derived")
	}
	if km.Dir() != "" {
		t.Errorf("in-memory manager Dir() = %q, want empty", km.Dir())
	}
}

func TestFromKeys_rejectsBadInput(t *testing.T) {
	priv, pub := genPair(t)
	_, otherPub := genPair(t)
	good := make([]byte, 32)

	cases := map[string]func() error{
		"mismatched pair": func() error { _, e := keymanager.FromKeys(priv, otherPub, good); return e },
		"short secret":    func() error { _, e := keymanager.FromKeys(priv, pub, []byte("x")); return e },
		"nil private":     func() error { _, e := keymanager.FromKeys(nil, pub, good); return e },
	}
	for name, fn := range cases {
		if fn() == nil {
			t.Errorf("%s: expected an error, got nil", name)
		}
	}
}

func TestFromPEM_roundTripAndGarbage(t *testing.T) {
	priv, pub := genPair(t)
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	privDER, _ := x509.MarshalPKCS8PrivateKey(priv)
	pubDER, _ := x509.MarshalPKIXPublicKey(pub)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	if _, err := keymanager.FromPEM(privPEM, pubPEM, secret); err != nil {
		t.Fatalf("FromPEM round-trip: %v", err)
	}
	if _, err := keymanager.FromPEM([]byte("garbage"), pubPEM, secret); err == nil {
		t.Error("expected an error for a non-PEM private key")
	}
}
