package stagingtest_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/seams"
	"github.com/Glyndor/authcore/internal/keymanager/staging/stagingtest"
)

func TestSilentLogImplementsTheLogger(t *testing.T) {
	var log layout.Logger = stagingtest.SilentLog{}
	log.Info("x %d", 1)
	log.Warn("x %d", 1)
}

func TestWithFaultAtInstallsAndRestoresTheSeam(t *testing.T) {
	sentinel := errors.New("boom")
	t.Run("installed", func(t *testing.T) {
		stagingtest.WithFaultAt(t, func(string) error { return sentinel })
		if err := seams.Fault("staged"); !errors.Is(err, sentinel) {
			t.Fatalf("Fault = %v, want the sentinel", err)
		}
	})
	t.Run("nil never faults", func(t *testing.T) {
		stagingtest.WithFaultAt(t, nil)
		if err := seams.Fault("staged"); err != nil {
			t.Fatalf("Fault = %v, want nil", err)
		}
	})
	if err := seams.Fault("staged"); err != nil {
		t.Fatalf("the seam was not restored: %v", err)
	}
}

func TestWithLinkFileInstallsAndRestoresTheSeam(t *testing.T) {
	stagingtest.PosixOnly(t)
	sentinel := errors.New("no links")
	t.Run("installed", func(t *testing.T) {
		stagingtest.WithLinkFile(t, func(string, string) error { return sentinel })
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

func TestStagingDirsListsOnlyStagingEntries(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{layout.StagingPrefix + "aa", "other"} {
		if err := os.Mkdir(filepath.Join(dir, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	got := stagingtest.StagingDirs(t, dir)
	if len(got) != 1 || got[0] != layout.StagingPrefix+"aa" {
		t.Fatalf("StagingDirs = %v, want the one staging entry", got)
	}
}
