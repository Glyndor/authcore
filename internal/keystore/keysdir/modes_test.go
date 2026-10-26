//go:build unix

package keysdir_test

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/Glyndor/authcore/internal/keystore/keysdir"
)

// A keys directory created on the caller's behalf is owner-only: it is where
// the private key will be written.
func TestCheckDir_CreatesTheDirectoryOwnerOnly(t *testing.T) {
	old := syscall.Umask(0)
	t.Cleanup(func() { syscall.Umask(old) })
	dir := filepath.Join(t.TempDir(), "keys")

	if err := keysdir.CheckDir(dir); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o700 {
		t.Fatalf("mode = %04o, want 0700", got)
	}
}
