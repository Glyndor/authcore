package recoverytest_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/recovery/recoverytest"
)

func TestSeedKeysWritesACompleteSet(t *testing.T) {
	dir := recoverytest.MustSeed(t, filepath.Join(t.TempDir(), "keys"))
	if !recoverytest.Complete(t, dir) {
		t.Fatal("seeded directory is not a complete set")
	}
	if err := os.Remove(filepath.Join(dir, layout.FilePublicKey)); err != nil {
		t.Fatal(err)
	}
	if recoverytest.Complete(t, dir) {
		t.Fatal("a set missing a file reported complete")
	}
}

func TestSeedKeysReportsAnUncreatableDirectory(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := recoverytest.SeedKeys(filepath.Join(file, "keys")); err == nil {
		t.Fatal("SeedKeys under a regular file returned nil")
	}
}

func TestStagingFromCopiesTheThreeFiles(t *testing.T) {
	recoverytest.PosixOnly(t)
	src := recoverytest.MustSeed(t, filepath.Join(t.TempDir(), "src"))
	dir := t.TempDir()
	staging := recoverytest.StagingFrom(t, dir, "abc", src)
	if filepath.Base(staging) != layout.StagingPrefix+"abc" {
		t.Fatalf("staging = %q", staging)
	}
	for _, name := range layout.KeyFileNames() {
		if _, err := os.Stat(filepath.Join(staging, name)); err != nil {
			t.Errorf("staged %s: %v", name, err)
		}
	}
}

func TestRecordingLogCountsAndMatches(t *testing.T) {
	var l recoverytest.RecordingLog
	l.Info("ignored")
	l.Warn("one %q", "alpha")
	l.Warn("two", "alpha", 2)
	l.Warn("three")
	if !l.WarnContains("alpha") || l.WarnContains("missing") {
		t.Errorf("WarnContains wrong over %v", l.Warns)
	}
	if got := l.CountWarns("alpha"); got != 2 {
		t.Errorf("CountWarns(alpha) = %d, want 2", got)
	}
	recoverytest.SilentLog{}.Info("x")
	recoverytest.SilentLog{}.Warn("x")
}
