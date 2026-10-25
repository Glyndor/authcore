package createset

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/staging/stagingtest"
)

// A KeysDir that turns unreadable after the first sync fails at the last one;
// the cleanup still works there and nothing is left behind.
func TestCreate_lateSyncFailureLeavesNoStagedKeys(t *testing.T) {
	stagingtest.PosixOnly(t)
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory mode bits")
	}
	dir := t.TempDir()
	t.Cleanup(func() { _ = os.Chmod(dir, 0700) })
	pinNameAndHookKeyGeneration(t, func() error { return os.Chmod(dir, 0300) })

	_, _, _, _, err := Create(dir)
	if err == nil || !strings.Contains(err.Error(), "sync keys directory") || strings.Contains(err.Error(), "could not remove") {
		t.Fatalf("Create = %v, want only the keys-directory sync failure", err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if left := stagingtest.StagingDirs(t, dir); len(left) != 0 {
		t.Errorf("staging directories left: %v", left)
	}
}

func TestDiscard_reportsAnEntryThatCannotBeRemoved(t *testing.T) {
	dir := t.TempDir()
	staging := filepath.Join(dir, midwayName)
	blocker := filepath.Join(staging, layout.FilePrivateKey)
	if err := os.MkdirAll(filepath.Join(blocker, "inside"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := Discard(staging); err == nil || !strings.Contains(err.Error(), "could not remove staging directory") {
		t.Fatalf("Discard = %v", err)
	}
}
