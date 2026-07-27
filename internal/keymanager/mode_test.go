package keymanager_test

import (
	"os"
	"runtime"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager"
)

// seededDir returns a key directory that already holds its key material.
func seededDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if _, err := keymanager.New(dir, testLogger{t}); err != nil {
		t.Fatalf("seed keymanager.New(): %v", err)
	}
	return dir
}

func modeOf(t *testing.T, dir string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat %s: %v", dir, err)
	}
	return fi.Mode().Perm()
}

// An operator who hands authcore a deliberately tighter KeysDir keeps it. This
// directory holds the Ed25519 private key and the refresh secret, so widening
// its permissions unasked is the opposite of what the tightening exists for.
func TestNew_doesNotLoosenARestrictiveKeysDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits do not apply on Windows")
	}
	dir := seededDir(t)
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatalf("restrict directory: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0700) })

	if _, err := keymanager.New(dir, testLogger{t}); err != nil {
		t.Fatalf("keymanager.New(): %v", err)
	}

	if got := modeOf(t, dir); got != 0500 {
		t.Errorf("key directory mode = %04o, want 0500 left alone", got)
	}
}

// The tightening the comment exists for still has to happen: a volume-mounted
// or pre-created directory that arrives world-readable is closed to the owner.
func TestNew_tightensAnOpenKeysDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits do not apply on Windows")
	}
	dir := seededDir(t)
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatalf("loosen directory: %v", err)
	}

	if _, err := keymanager.New(dir, testLogger{t}); err != nil {
		t.Fatalf("keymanager.New(): %v", err)
	}

	if got := modeOf(t, dir); got != 0700 {
		t.Errorf("key directory mode = %04o, want 0700 after tightening", got)
	}
}
