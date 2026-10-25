//go:build unix

package hostile

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
)

// A generation that fails must not leave unpublished key material behind.
func TestHostile_FailedGenerationLeavesNoStagedKeys(t *testing.T) {
	requireNonRoot(t)
	sb := newSandbox(t)
	dir := sb.keysDir(t)
	restoreMode(t, dir)
	if err := os.Chmod(dir, 0o300); err != nil {
		t.Fatal(err)
	}

	r := open(t, dir, false)

	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if r.err == nil {
		t.Skip("the sync did not fail on this filesystem, so the failure path was not reached")
	}
	if left := stagingDirs(t, dir); len(left) != 0 {
		t.Errorf("a failed generation left staging directories: %v", left)
	}
	for _, n := range layout.KeyFileNames() {
		if _, err := os.Lstat(filepath.Join(dir, n)); err == nil {
			t.Errorf("a failed generation published %s", n)
		}
	}
}
