package loadonly_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/recovery/recoverytest"
)

// Load makes no write, but it still refuses a directory that holds two
// initialisations: the evidence is read from the directory, so the answer is
// the same on every start.
func TestLoadRefusesAStagingDirectoryThatContradictsThePublishedKeys(t *testing.T) {
	dir := t.TempDir()
	if _, err := New(dir, testLogger{t}); err != nil {
		t.Fatal(err)
	}
	staging := recoverytest.StagingFrom(t, dir, "copy", dir)
	if err := os.WriteFile(filepath.Join(staging, layout.FilePublicKey), []byte("another set"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := Load(dir, testLogger{t})
	if err == nil || !strings.Contains(err.Error(), "two different initialisations") {
		t.Fatalf("Load = %v, want the two-initialisations refusal", err)
	}
}

// A refresh secret that is not the one metadata.json bound to the key pair is
// refused by Load as it is by New.
func TestLoadRefusesARefreshSecretThatDoesNotBelongToTheKeyPair(t *testing.T) {
	dir := t.TempDir()
	if _, err := New(dir, testLogger{t}); err != nil {
		t.Fatal(err)
	}
	other := t.TempDir()
	if _, err := New(other, testLogger{t}); err != nil {
		t.Fatal(err)
	}
	recoverytest.CopyFile(t, filepath.Join(other, layout.FileRefreshSecret), filepath.Join(dir, layout.FileRefreshSecret))

	_, err := Load(dir, testLogger{t})
	if err == nil || !strings.Contains(err.Error(), "does not belong to its key pair") {
		t.Fatalf("Load = %v, want the secret mismatch refusal", err)
	}
}

func TestLoadNamesAFileFoundWhereTheDirectoryShouldBe(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path, testLogger{t})
	if err == nil || !strings.Contains(err.Error(), "authcore must be able to read") {
		t.Fatalf("Load = %v, want the not-a-directory refusal", err)
	}
}
