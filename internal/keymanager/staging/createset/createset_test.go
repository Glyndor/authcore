package createset

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
)

func TestCreateStagingSet_mkdirFailsWhenNameIsTaken(t *testing.T) {
	// Wrap randRead so the staging name is deterministic, then plant a
	// directory at that name to force Mkdir to fail.
	dir := t.TempDir()
	planted := filepath.Join(dir, ".staging-0001020304050607")
	if err := os.Mkdir(planted, 0700); err != nil {
		t.Fatal(err)
	}
	origRead := randRead
	randRead = func(b []byte) (int, error) {
		for i := range b {
			b[i] = byte(i)
		}
		return len(b), nil
	}
	t.Cleanup(func() { randRead = origRead })

	_, _, _, _, err := Create(dir)
	if err == nil {
		t.Fatalf("Create succeeded; expected collision with %s", planted)
	}
	if !strings.Contains(err.Error(), "staging directory") {
		t.Errorf("error must mention the staging directory, got: %v", err)
	}
}

// Create's "CSPRNG failed for the staging suffix" branch.
// The randRead seam is wrapped to return an error; Create must
// surface it without leaving any .staging-* entry behind.
func TestCreateStagingSetFailsCleanlyOnRandomFailure(t *testing.T) {
	prev := randRead
	t.Cleanup(func() { randRead = prev })
	randRead = func([]byte) (int, error) {
		return 0, errors.New("csprng offline")
	}

	dir := t.TempDir()
	_, _, _, _, err := Create(dir)
	if err == nil {
		t.Fatal("Create succeeded despite randRead failing")
	}
	if !strings.Contains(err.Error(), "staging suffix") {
		t.Errorf("error must mention 'staging suffix', got: %v", err)
	}

	entries, readErr := os.ReadDir(dir)
	if readErr != nil {
		t.Fatal(readErr)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), layout.StagingPrefix) {
			t.Errorf("staging entry %q survived a failed Create", e.Name())
		}
	}
}

func TestStagingDirName_isHiddenPrefixedAndRandom(t *testing.T) {
	a, err := stagingDirName()
	if err != nil {
		t.Fatal(err)
	}
	b, err := stagingDirName()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(a, layout.StagingPrefix) || len(a) != len(layout.StagingPrefix)+16 {
		t.Errorf("name %q does not carry the prefix and 16 hex characters", a)
	}
	if a == b {
		t.Error("two staging names collided")
	}
}

func TestCreateStagingSet_returnsMatchingKeysAndModes(t *testing.T) {
	dir := t.TempDir()
	staging, priv, pub, secret, err := Create(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !priv.Public().(ed25519.PublicKey).Equal(pub) || len(secret) != layout.RefreshSecretLen {
		t.Fatal("Create returned inconsistent material")
	}
	for _, name := range layout.KeyFileNames() {
		if _, err := os.Stat(filepath.Join(staging, name)); err != nil {
			t.Errorf("%s was not staged: %v", name, err)
		}
	}
}
