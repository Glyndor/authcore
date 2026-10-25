package bootstraptest_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/bootstrap/bootstraptest"
	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/material"
	"github.com/Glyndor/authcore/internal/keymanager/seams"
)

func TestNewAndLoadAgreeOnTheSameDirectory(t *testing.T) {
	dir := t.TempDir()
	created, err := bootstraptest.New(dir, bootstraptest.SilentLog{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	loaded, err := bootstraptest.Load(dir, bootstraptest.SilentLog{})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !bytes.Equal(created.PrivateKey(), loaded.PrivateKey()) ||
		!bytes.Equal(created.PublicKey(), loaded.PublicKey()) ||
		!bytes.Equal(created.RefreshSecret(), loaded.RefreshSecret()) {
		t.Error("Load must return the key set New generated")
	}
	if created.Dir() != dir || loaded.Dir() != dir {
		t.Errorf("Dir() = %q and %q, want %q", created.Dir(), loaded.Dir(), dir)
	}
	if created.KeyID() != material.KeyID(created.PublicKey()) {
		t.Error("KeyID must derive from the public key")
	}
}

func TestNewAndLoadReportErrors(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := bootstraptest.New(filepath.Join(file, "keys"), bootstraptest.SilentLog{}); err == nil {
		t.Error("New below a regular file must fail")
	}
	if _, err := bootstraptest.Load(t.TempDir(), bootstraptest.SilentLog{}); err == nil {
		t.Error("Load of an empty directory must fail")
	}
}

func TestOpenOKSeedsAndReadsTheSet(t *testing.T) {
	dir := t.TempDir()
	rec := &bootstraptest.Recorder{}
	priv, pub, secret := bootstraptest.OpenOK(t, dir, rec)
	if len(priv) == 0 || len(pub) == 0 || len(secret) == 0 {
		t.Fatal("OpenOK returned an empty key set")
	}
	if !rec.Warned("empty") || rec.CountWarns("empty") != 1 {
		t.Errorf("fresh generation must warn exactly once: %q", rec.Warns)
	}
	rec.Info("seen %d", 1)
	if len(rec.Infos) == 0 || rec.Infos[len(rec.Infos)-1] != "seen 1" {
		t.Errorf("Info not recorded: %q", rec.Infos)
	}
	if rec.Warned("no such fragment") {
		t.Error("Warned matched a fragment that was never logged")
	}
	set := bootstraptest.ReadSet(t, dir)
	published := bootstraptest.ReadPublishedSet(t, dir)
	for i := range set {
		if len(set[i]) == 0 || !bytes.Equal(set[i], published[i]) {
			t.Errorf("file %d: ReadSet and ReadPublishedSet disagree", i)
		}
	}
	if got := bootstraptest.ReadFile(t, dir, layout.FileGitignore); len(got) == 0 {
		t.Error("ReadFile returned an empty .gitignore")
	}
	if dirs := bootstraptest.ListStagingDirs(t, dir); len(dirs) != 0 {
		t.Errorf("a finished init left staging directories: %v", dirs)
	}
	if got := bootstraptest.SeedValidDir(t); len(bootstraptest.ReadSet(t, got)) != 3 {
		t.Error("SeedValidDir must hold the three key files")
	}
}

func TestReadPublishedSetToleratesMissingFiles(t *testing.T) {
	set := bootstraptest.ReadPublishedSet(t, t.TempDir())
	for i, b := range set {
		if b != nil {
			t.Errorf("file %d: want nil for a missing file", i)
		}
	}
}

func TestListStagingDirsSkipsFilesAndLinks(t *testing.T) {
	dir := t.TempDir()
	real := layout.StagingPrefix + "real"
	if err := os.Mkdir(filepath.Join(dir, real), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, layout.StagingPrefix+"file"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(dir, layout.StagingPrefix+"link")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "unrelated"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	got := bootstraptest.ListStagingDirs(t, dir)
	if len(got) != 1 || got[0] != real {
		t.Errorf("ListStagingDirs = %v, want only %q", got, real)
	}
}

func TestSeamHelpersRestoreTheOriginals(t *testing.T) {
	boom := errors.New("boom")
	t.Run("inner", func(t *testing.T) {
		bootstraptest.WithFault(t, func(string) error { return boom })
		if !errors.Is(seams.Fault("x"), boom) {
			t.Error("WithFault did not install the hook")
		}
		bootstraptest.WithFaultAt(t, nil)
		if seams.Fault("x") != nil {
			t.Error("WithFaultAt(nil) must install a hook that never fails")
		}
		bootstraptest.WithFaultAt(t, func(string) error { return boom })
		if !errors.Is(seams.Fault("x"), boom) {
			t.Error("WithFaultAt did not install the hook")
		}
		bootstraptest.WithLinkFile(t, func(string, string) error { return boom })
		if !errors.Is(seams.LinkFile("a", "b"), boom) {
			t.Error("WithLinkFile did not install the hook")
		}
	})
	if seams.Fault("x") != nil {
		t.Error("the fault hook leaked out of the test")
	}
	if err := seams.LinkFile("/nonexistent/a", "/nonexistent/b"); errors.Is(err, boom) {
		t.Error("the link hook leaked out of the test")
	}
}

func TestCopyFileAndHexDecode(t *testing.T) {
	src := filepath.Join(t.TempDir(), "src")
	dst := filepath.Join(t.TempDir(), "dst")
	if err := os.WriteFile(src, []byte("0aff\n"), 0600); err != nil {
		t.Fatal(err)
	}
	bootstraptest.CopyFile(t, src, dst)
	got := bootstraptest.MustHexDecode(t, bootstraptest.ReadFile(t, filepath.Dir(dst), "dst"))
	if !bytes.Equal(got, []byte{0x0a, 0xff}) {
		t.Errorf("decoded %x, want 0aff", got)
	}
}

func TestLoggersAndSkips(t *testing.T) {
	bootstraptest.TestLogger{T: t}.Info("info %d", 1)
	bootstraptest.TestLogger{T: t}.Warn("warn %d", 1)
	var s bootstraptest.SilentLog
	s.Info("x")
	s.Warn("x")
	s.Error("x")
	s.Debug("x")

	rl := &bootstraptest.RecordingLog{}
	rl.Info("ignored")
	rl.Error("ignored")
	rl.Warn("first %s", "a")
	rl.Warn("bare")
	if !rl.WarnContains("first %s a") || !rl.WarnContains("bare") || rl.WarnContains("ignored") {
		t.Errorf("WarnContains disagrees with the entries: %v", rl.Entries)
	}
	if got := bootstraptest.FormatEntry(rl.Entries[0]); !strings.HasPrefix(got, "first %s") {
		t.Errorf("FormatEntry = %q", got)
	}

	bootstraptest.PosixOnly(t)
	if os.Geteuid() != 0 {
		bootstraptest.NotRoot(t)
	}
}
