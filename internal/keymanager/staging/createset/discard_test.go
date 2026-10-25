package createset

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/staging/stagingtest"
)

func TestDiscard_removesTheStagedFilesAndTheDirectory(t *testing.T) {
	dir := t.TempDir()
	staging := filepath.Join(dir, midwayName)
	if err := os.Mkdir(staging, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range layout.KeyFileNames()[:2] {
		if err := os.WriteFile(filepath.Join(staging, name), []byte("k"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := Discard(staging); err != nil {
		t.Fatalf("Discard: %v", err)
	}
	if _, err := os.Lstat(staging); err == nil {
		t.Error("the staging directory is still there")
	}
	if err := Discard(staging); err != nil {
		t.Errorf("Discard of a directory that is already gone: %v", err)
	}
}

// What cannot be removed is reported with the directory's name, not swallowed.
func TestDiscard_reportsWhatItCouldNotRemove(t *testing.T) {
	dir := t.TempDir()
	staging := filepath.Join(dir, midwayName)
	if err := os.Mkdir(staging, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staging, "stray"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	err := Discard(staging)
	if err == nil || !strings.Contains(err.Error(), staging) {
		t.Fatalf("Discard = %v, want an error naming %q", err, staging)
	}
}

// When the cleanup of a failed generation fails as well, the caller is told.
func TestCreate_aFailedCleanupIsPartOfTheError(t *testing.T) {
	dir := t.TempDir()
	pinNameAndHookKeyGeneration(t, func() error {
		if err := os.WriteFile(filepath.Join(dir, midwayName, "stray"), []byte("x"), 0600); err != nil {
			return err
		}
		return errors.New("entropy offline")
	})

	_, _, _, _, err := Create(dir)
	if err == nil || !strings.Contains(err.Error(), "entropy offline") ||
		!strings.Contains(err.Error(), "could not remove staging directory") {
		t.Fatalf("Create = %v, want both the failure and the failed cleanup", err)
	}
}

// A KeysDir that can be written and searched but not read fails before any key
// is generated, so there is nothing to clean up and nothing left behind.
func TestCreate_unsyncableDirectoryFailsBeforeAnythingIsWritten(t *testing.T) {
	stagingtest.PosixOnly(t)
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory mode bits")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0300); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0700) })

	_, _, _, _, err := Create(dir)
	if err == nil || !strings.Contains(err.Error(), "sync keys directory") {
		t.Fatalf("Create = %v, want the keys-directory sync failure", err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("a failed Create left %d entries behind", len(entries))
	}
}
