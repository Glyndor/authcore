package preflight

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
)

func TestSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on Windows")
	}

	empty := t.TempDir()
	if err := Symlinks(empty); err != nil {
		t.Fatalf("an empty directory is not a symlink: %v", err)
	}

	for _, name := range layout.KeyFileNames() {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Symlink(filepath.Join(t.TempDir(), "nowhere"), filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}
			err := Symlinks(dir)
			if err == nil || !strings.Contains(err.Error(), "symlink") {
				t.Fatalf("Symlinks = %v, want a refusal naming the symlink", err)
			}
		})
	}
}

// Lstat failing for a reason other than "absent" is refused too: the slot
// cannot be shown to be empty.
func TestSymlinks_unclassifiableSlotIsRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows reports a path below a regular file as not found (ERROR_PATH_NOT_FOUND) instead of not a directory, so the error this test pins cannot occur")
	}
	dir := t.TempDir()
	notADir := filepath.Join(dir, "file")
	if err := os.WriteFile(notADir, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	// dir/file/<name>: Lstat answers ENOTDIR, not ENOENT.
	if err := Symlinks(notADir); err == nil {
		t.Fatal("a path below a regular file must not pass the preflight")
	}
}
