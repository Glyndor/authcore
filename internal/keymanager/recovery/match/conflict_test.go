package match

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/recovery/recoverytest"
)

func TestConflict(t *testing.T) {
	recoverytest.PosixOnly(t)
	dir := recoverytest.MustSeed(t, t.TempDir())

	if name, err := Conflict(dir); err != nil || name != "" {
		t.Fatalf("no staging: %q, %v", name, err)
	}

	st := recoverytest.StagingFrom(t, dir, "copy", dir)
	if name, err := Conflict(dir); err != nil || name != "" {
		t.Fatalf("identical staging: %q, %v", name, err)
	}

	other := recoverytest.MustSeed(t, t.TempDir())
	recoverytest.CopyFile(t, filepath.Join(other, layout.FileRefreshSecret), filepath.Join(dir, layout.FileRefreshSecret))
	if name, err := Conflict(dir); err != nil || name != layout.FileRefreshSecret {
		t.Fatalf("different secret: %q, %v", name, err)
	}

	// A staging directory of another initialisation (other private key) says
	// nothing about the published files.
	if err := os.RemoveAll(st); err != nil {
		t.Fatal(err)
	}
	recoverytest.StagingFrom(t, dir, "other", other)
	if name, err := Conflict(dir); err != nil || name != "" {
		t.Fatalf("unrelated staging: %q, %v", name, err)
	}
}

func TestConflictIgnoresAnUnlistableDirectory(t *testing.T) {
	if name, err := Conflict(filepath.Join(t.TempDir(), "absent")); err != nil || name != "" {
		t.Fatalf("%q, %v", name, err)
	}
}

func TestConflictIgnoresAPartialPublishedSet(t *testing.T) {
	recoverytest.PosixOnly(t)
	dir := recoverytest.MustSeed(t, t.TempDir())
	recoverytest.StagingFrom(t, dir, "copy", dir)
	if err := os.Remove(filepath.Join(dir, layout.FileRefreshSecret)); err != nil {
		t.Fatal(err)
	}
	if name, err := Conflict(dir); err != nil || name != "" {
		t.Fatalf("%q, %v", name, err)
	}
}
