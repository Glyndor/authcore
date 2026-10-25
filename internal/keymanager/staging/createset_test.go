package staging

import (
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

	_, _, _, _, err := createStagingSet(dir)
	if err == nil {
		t.Fatalf("createStagingSet succeeded; expected collision with %s", planted)
	}
	if !strings.Contains(err.Error(), "staging directory") {
		t.Errorf("error must mention the staging directory, got: %v", err)
	}
}

// createStagingSet's "CSPRNG failed for the staging suffix" branch.
// The randRead seam is wrapped to return an error; createStagingSet must
// surface it without leaving any .staging-* entry behind.
func TestCreateStagingSetFailsCleanlyOnRandomFailure(t *testing.T) {
	prev := randRead
	t.Cleanup(func() { randRead = prev })
	randRead = func([]byte) (int, error) {
		return 0, errors.New("csprng offline")
	}

	dir := t.TempDir()
	_, _, _, _, err := createStagingSet(dir)
	if err == nil {
		t.Fatal("createStagingSet succeeded despite randRead failing")
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
			t.Errorf("staging entry %q survived a failed createStagingSet", e.Name())
		}
	}
}
