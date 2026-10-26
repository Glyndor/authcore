//go:build unix

package createset_test

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/staging/createset"
)

// The staging directory holds the private key before it is published, so it
// is owner-only from the moment it exists, and each file gets its own mode.
func TestCreate_StagesWithExactModes(t *testing.T) {
	old := syscall.Umask(0)
	t.Cleanup(func() { syscall.Umask(old) })

	staging, _, _, _, err := createset.Create(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]os.FileMode{
		".":                      0o700,
		layout.FilePrivateKey:    0o600,
		layout.FilePublicKey:     0o644,
		layout.FileRefreshSecret: 0o600,
	}
	for name, mode := range want {
		fi, err := os.Stat(filepath.Join(staging, name))
		if err != nil {
			t.Fatal(err)
		}
		if got := fi.Mode().Perm(); got != mode {
			t.Errorf("%s: mode %04o, want %04o", name, got, mode)
		}
	}
}
