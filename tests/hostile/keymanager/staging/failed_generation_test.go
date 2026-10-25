//go:build unix

package staging

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/tests/hostile/keymanager/hostiletest"
)

// A generation that fails must not leave unpublished key material behind.
func TestHostile_FailedGenerationLeavesNoStagedKeys(t *testing.T) {
	hostiletest.RequireNonRoot(t)
	sb := hostiletest.NewSandbox(t)
	dir := sb.KeysDir(t)
	hostiletest.RestoreMode(t, dir)
	if err := os.Chmod(dir, 0o300); err != nil {
		t.Fatal(err)
	}

	r := hostiletest.Open(t, dir, false)

	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if r.Err == nil {
		t.Skip("the sync did not fail on this filesystem, so the failure path was not reached")
	}
	if left := hostiletest.StagingDirs(t, dir); len(left) != 0 {
		t.Errorf("a failed generation left staging directories: %v", left)
	}
	for _, n := range layout.KeyFileNames() {
		if _, err := os.Lstat(filepath.Join(dir, n)); err == nil {
			t.Errorf("a failed generation published %s", n)
		}
	}
}
