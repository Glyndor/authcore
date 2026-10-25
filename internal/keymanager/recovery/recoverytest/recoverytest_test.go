package recoverytest_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/recovery/recoverytest"
	"github.com/Glyndor/authcore/internal/keymanager/seams"
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

func TestListStagingDirsSkipsSymlinksAndFiles(t *testing.T) {
	recoverytest.PosixOnly(t)
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, layout.StagingPrefix+"real"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, layout.StagingPrefix+"file"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(dir, filepath.Join(dir, layout.StagingPrefix+"link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "unrelated"), 0700); err != nil {
		t.Fatal(err)
	}
	got := recoverytest.ListStagingDirs(t, dir)
	if len(got) != 1 || got[0] != layout.StagingPrefix+"real" {
		t.Fatalf("ListStagingDirs = %v, want only the real staging directory", got)
	}
}

func TestWithLinkFileInstallsAndRestoresTheSeam(t *testing.T) {
	recoverytest.PosixOnly(t)
	sentinel := errors.New("no links")
	t.Run("installed", func(t *testing.T) {
		recoverytest.WithLinkFile(t, func(string, string) error { return sentinel })
		if err := seams.LinkFile("a", "b"); !errors.Is(err, sentinel) {
			t.Fatalf("LinkFile = %v, want the sentinel", err)
		}
	})
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.WriteFile(src, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := seams.LinkFile(src, filepath.Join(dir, "dst")); err != nil {
		t.Fatalf("the seam was not restored: %v", err)
	}
}
