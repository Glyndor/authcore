package keymanager

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

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
