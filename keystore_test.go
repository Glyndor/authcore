package authcore_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/Glyndor/authcore"
)

func genMaterial(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey, []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatalf("generate secret: %v", err)
	}
	return priv, pub, secret
}

func TestNewKeyStoreFromKeys_used(t *testing.T) {
	priv, pub, secret := genMaterial(t)
	ks, err := authcore.NewKeyStoreFromKeys(priv, pub, secret)
	if err != nil {
		t.Fatalf("NewKeyStoreFromKeys: %v", err)
	}

	cfg := authcore.DefaultConfig()
	cfg.EnableLogs = false
	cfg.KeyStore = ks
	cfg.KeysDir = "" // must be ignored

	ac, err := authcore.New(cfg)
	if err != nil {
		t.Fatalf("New with KeyStore: %v", err)
	}
	if !ac.Keys().PrivateKey().Equal(priv) {
		t.Error("module did not use the injected private key")
	}
	if string(ac.Keys().RefreshSecret()) != string(secret) {
		t.Error("module did not use the injected refresh secret")
	}
}

func TestNewKeyStoreFromKeys_mismatchedPairRejected(t *testing.T) {
	priv, _, secret := genMaterial(t)
	_, otherPub, _ := genMaterial(t)
	if _, err := authcore.NewKeyStoreFromKeys(priv, otherPub, secret); err == nil {
		t.Error("expected an error for a mismatched key pair")
	}
}

func TestNewKeyStoreFromKeys_badSecretRejected(t *testing.T) {
	priv, pub, _ := genMaterial(t)
	if _, err := authcore.NewKeyStoreFromKeys(priv, pub, []byte("too-short")); err == nil {
		t.Error("expected an error for a wrong-length refresh secret")
	}
}

func TestNewKeyStoreFromPEM_roundTrip(t *testing.T) {
	priv, pub, secret := genMaterial(t)
	privDER, _ := x509.MarshalPKCS8PrivateKey(priv)
	pubDER, _ := x509.MarshalPKIXPublicKey(pub)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	ks, err := authcore.NewKeyStoreFromPEM(privPEM, pubPEM, secret)
	if err != nil {
		t.Fatalf("NewKeyStoreFromPEM: %v", err)
	}
	cfg := authcore.DefaultConfig()
	cfg.EnableLogs = false
	cfg.KeyStore = ks
	ac, err := authcore.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !ac.Keys().PublicKey().Equal(pub) {
		t.Error("module did not load the PEM public key")
	}
}

func TestNewKeyStoreFromPEM_garbageRejected(t *testing.T) {
	_, _, secret := genMaterial(t)
	if _, err := authcore.NewKeyStoreFromPEM([]byte("nope"), []byte("nope"), secret); err == nil {
		t.Error("expected an error for non-PEM input")
	}
}

func TestNew_keyStoreBypassesKeysDirValidation(t *testing.T) {
	// A KeyStore makes KeysDir irrelevant, so even an invalid KeysDir must not
	// block startup.
	priv, pub, secret := genMaterial(t)
	ks, err := authcore.NewKeyStoreFromKeys(priv, pub, secret)
	if err != nil {
		t.Fatalf("NewKeyStoreFromKeys: %v", err)
	}
	cfg := authcore.DefaultConfig()
	cfg.EnableLogs = false
	cfg.KeyStore = ks
	cfg.KeysDir = string([]byte{0}) // would fail validateKeysDir if it ran

	if _, err := authcore.New(cfg); err != nil {
		t.Errorf("KeyStore must bypass KeysDir validation, got %v", err)
	}
}
