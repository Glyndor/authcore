package keymanager_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager"
)

// writeValidEd25519Pair writes a real Ed25519 key pair into dir so the loader
// reaches the refresh-secret step.
func writeValidEd25519Pair(t *testing.T, dir string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519: %v", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal private: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal public: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ed25519_private.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}), 0600); err != nil {
		t.Fatalf("write private: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ed25519_public.pem"), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0600); err != nil {
		t.Fatalf("write public: %v", err)
	}
}

// TestNew_unreadableRefreshSecretRejected places a valid key pair beside a
// refresh_secret.key that is a directory. All three paths exist, so the
// consistency check passes and the loader proceeds — but reading the "file"
// fails, exercising readCapped's read-error path.
func TestNew_unreadableRefreshSecretRejected(t *testing.T) {
	dir := t.TempDir()
	writeValidEd25519Pair(t, dir)
	if err := os.Mkdir(filepath.Join(dir, "refresh_secret.key"), 0700); err != nil {
		t.Fatalf("seed refresh-secret directory: %v", err)
	}

	if _, err := keymanager.New(dir, testLogger{t}); err == nil {
		t.Error("expected New() to fail when refresh_secret.key is unreadable, got nil")
	}
}

// TestNew_nonEd25519KeyPairRejected seeds a syntactically valid PEM key pair
// that parses cleanly but is ECDSA, not Ed25519. This exercises the type
// assertions in readPrivateKey/readPublicKey — distinct from the existing
// corrupt-PEM and cross-PEM cases, where parsing itself fails.
func TestNew_nonEd25519KeyPairRejected(t *testing.T) {
	dir := t.TempDir()

	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa key: %v", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(ec)
	if err != nil {
		t.Fatalf("marshal ecdsa private: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&ec.PublicKey)
	if err != nil {
		t.Fatalf("marshal ecdsa public: %v", err)
	}

	write := func(name, blockType string, der []byte) {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0600); err != nil {
			t.Fatalf("write %q: %v", path, err)
		}
	}
	write("ed25519_private.pem", "PRIVATE KEY", privDER)
	write("ed25519_public.pem", "PUBLIC KEY", pubDER)

	if _, err := keymanager.New(dir, testLogger{t}); err == nil {
		t.Error("expected New() to reject a non-Ed25519 (ECDSA) key pair, got nil")
	}
}
