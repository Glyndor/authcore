package keymanager

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

// If the public key cannot be written after the private one already has been,
// the private key is removed again — otherwise the next start finds a
// half-populated directory and refuses to run at all. The cleanup is
// unreachable through New, because checkKeyDirConsistency rejects a partial
// directory before generation is ever attempted, so it is driven directly.
//
// A directory standing where the file should go makes the write fail on every
// platform without needing permission games.
func TestGenerateAndSaveEd25519_removesThePrivateKeyIfThePublicWriteFails(t *testing.T) {
	dir := t.TempDir()
	privPath := filepath.Join(dir, filePrivateKey)
	pubPath := filepath.Join(dir, filePublicKey)
	if err := os.Mkdir(pubPath, 0700); err != nil {
		t.Fatalf("plant a directory at the public key path: %v", err)
	}

	_, _, err := generateAndSaveEd25519(privPath, pubPath)
	if err == nil {
		t.Fatal("the generation must fail when the public key cannot be written")
	}
	if _, err := os.Stat(privPath); !os.IsNotExist(err) {
		t.Fatalf("the private key must not survive a failed pair write, stat gave: %v", err)
	}
}

func TestGenerateAndSaveEd25519_failsWhenThePrivateKeyCannotBeWritten(t *testing.T) {
	dir := t.TempDir()
	privPath := filepath.Join(dir, filePrivateKey)
	if err := os.Mkdir(privPath, 0700); err != nil {
		t.Fatalf("plant a directory at the private key path: %v", err)
	}

	if _, _, err := generateAndSaveEd25519(privPath, filepath.Join(dir, filePublicKey)); err == nil {
		t.Fatal("the generation must fail when the private key cannot be written")
	}
}

func TestGenerateAndSaveRefreshSecret_failsWhenItCannotBeWritten(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, fileRefreshSecret)
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatalf("plant a directory at the secret path: %v", err)
	}

	if _, err := generateAndSaveRefreshSecret(path); err == nil {
		t.Fatal("the generation must fail when the secret cannot be written")
	}
}

// A descriptor that cannot be read at all is not the same as one that is
// absent: absent means the pre-marker layout and is adopted, while unreadable
// means the loader cannot tell what wrote the directory and must fail closed.
func TestNew_refusesAnUnreadableDescriptor(t *testing.T) {
	dir := t.TempDir()
	if _, err := New(dir, testLoggerInternal{t}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	path := filepath.Join(dir, fileMetadata)
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove descriptor: %v", err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatalf("plant a directory at the descriptor path: %v", err)
	}

	if _, err := New(dir, testLoggerInternal{t}); err == nil {
		t.Fatal("an unreadable descriptor must fail closed, not be treated as absent")
	}
}

// KeyID is exported for the JWT module to index rotated keys by the same
// derivation. Its own package never called it, so it read as 0% while being
// exercised from next door — asserted here so the number stops lying.
func TestKeyID_matchesTheManagersOwnDerivation(t *testing.T) {
	dir := t.TempDir()
	km, err := New(dir, testLoggerInternal{t})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	if got := KeyID(km.PublicKey()); got != km.KeyID() {
		t.Fatalf("KeyID(pub) = %q, want the manager's own %q", got, km.KeyID())
	}

	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if KeyID(other) == km.KeyID() {
		t.Fatal("two different keys must not share an id")
	}
}

type testLoggerInternal struct{ t *testing.T }

func (l testLoggerInternal) Info(msg string, args ...any) { l.t.Logf("[INFO] "+msg, args...) }
func (l testLoggerInternal) Warn(msg string, args ...any) { l.t.Logf("[WARN] "+msg, args...) }
