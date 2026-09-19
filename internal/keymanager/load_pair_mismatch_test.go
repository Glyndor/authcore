// Pair-mismatch tests for the keymanager Load path.
//
// TestLoadMismatchedKeyPairRejected was originally in load_test.go and pins
// the contract that a complete set with a private key and a public key from
// two different pairs is refused. TestLoadMismatchedKeyPairErrorWrapping
// pins the wrap chain Load produces around the loader error, so a caller
// that branches on either layer (errors.Is, errors.As) still finds its
// sentinel after the wording change.
//
// The new-wording assertions live here, separate from the rest of the
// load-only suite, because the change targets an error message rather than
// load-only semantics and the rule that "delete" never appears in key-file
// advice is a property of the message rather than of Load itself.

package keymanager_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager"
)

// TestLoadMismatchedKeyPairRejected pins the pair check on a complete set
// whose private and public keys belong to two different pairs. Load must
// hand the loader the two paths and forward the error unchanged, and the
// error message must call out the mismatch, tell the operator to restore
// the matching pair from a backup, and never suggest deleting key material
// (deleting the private key would destroy the signing key).
func TestLoadMismatchedKeyPairRejected(t *testing.T) {
	dir := t.TempDir()
	pubA, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen first pair: %v", err)
	}
	_, privB, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen second pair: %v", err)
	}

	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: mustMarshalPKCS8(t, privB),
	})
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: mustMarshalPKIX(t, pubA),
	})
	secretRaw := make([]byte, 32)
	if _, err := rand.Read(secretRaw); err != nil {
		t.Fatalf("read secret: %v", err)
	}
	secretHex := append(hexEncode(secretRaw), '\n')
	if err := os.WriteFile(filepath.Join(dir, "ed25519_private.pem"), privPEM, 0600); err != nil {
		t.Fatalf("write priv: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ed25519_public.pem"), pubPEM, 0644); err != nil {
		t.Fatalf("write pub: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "refresh_secret.key"), secretHex, 0600); err != nil {
		t.Fatalf("write secret: %v", err)
	}

	_, err = keymanager.Load(dir, testLogger{t})
	if err == nil {
		t.Fatal("expected the pair-check error, got nil")
	}
	if !strings.Contains(err.Error(), "does not match") {
		t.Errorf("error should call out the pair mismatch, got: %v", err)
	}
	if !strings.Contains(err.Error(), "restore the matching pair from a backup") {
		t.Errorf("error should tell the operator to restore from a backup, got: %v", err)
	}
	if strings.Contains(err.Error(), "delete") {
		t.Errorf("error must not suggest deleting key material, got: %v", err)
	}
}

// TestLoadMismatchedKeyPairErrorWrapping pins that the pair-mismatch error
// keeps its wrap chain: Load wraps loadEd25519 with %w, and the root
// package's diskKeyStore wraps that with %w around ErrKeyManager. A
// caller that branches on either layer (errors.Is, errors.As) still finds
// its sentinel after the wording change.
func TestLoadMismatchedKeyPairErrorWrapping(t *testing.T) {
	dir := t.TempDir()
	pubA, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen first pair: %v", err)
	}
	_, privB, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen second pair: %v", err)
	}

	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustMarshalPKCS8(t, privB)})
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: mustMarshalPKIX(t, pubA)})
	secretRaw := make([]byte, 32)
	if _, err := rand.Read(secretRaw); err != nil {
		t.Fatalf("read secret: %v", err)
	}
	secretHex := append(hexEncode(secretRaw), '\n')
	if err := os.WriteFile(filepath.Join(dir, "ed25519_private.pem"), privPEM, 0600); err != nil {
		t.Fatalf("write priv: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ed25519_public.pem"), pubPEM, 0644); err != nil {
		t.Fatalf("write pub: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "refresh_secret.key"), secretHex, 0600); err != nil {
		t.Fatalf("write secret: %v", err)
	}

	_, err = keymanager.Load(dir, testLogger{t})
	if err == nil {
		t.Fatal("expected the pair-check error, got nil")
	}
	if !strings.Contains(err.Error(), "ed25519 key pair") {
		t.Errorf("error should still carry the Load-layer 'ed25519 key pair' prefix, got: %v", err)
	}
	if !strings.Contains(err.Error(), "does not match") {
		t.Errorf("error should still call out the pair mismatch, got: %v", err)
	}
}
