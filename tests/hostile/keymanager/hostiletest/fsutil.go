//go:build unix

package hostiletest

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
)

// RestoreDirTree makes everything under dir removable again.
func RestoreDirTree(dir string) {
	for _, n := range append(layout.KeyFileNames(), layout.FileMetadata) {
		p := filepath.Join(dir, n)
		if fi, err := os.Lstat(p); err == nil && fi.Mode()&os.ModeSymlink == 0 {
			_ = os.Chmod(p, 0o700)
		}
	}
	_ = os.Chmod(dir, 0o700)
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if d != nil && d.IsDir() {
			_ = os.Chmod(p, 0o700)
		}
		return nil
	})
}

// ModeOf returns the mode of the file at path, following links.
func ModeOf(t testing.TB, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode()
}

// PublishedPrivate returns the private key file of dir, or nil when none was published.
func PublishedPrivate(t testing.TB, dir string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, layout.FilePrivateKey))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Mkfifo creates a named pipe at path.
func Mkfifo(t testing.TB, path string) {
	t.Helper()
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
}

// Mksocket creates a unix socket node at path. The bind happens in a short
// directory because sun_path is limited to about 108 bytes, then the node is
// renamed into place.
func Mksocket(t testing.TB, path string) {
	t.Helper()
	short, err := os.MkdirTemp("", "hs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(short) })
	l, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", filepath.Join(short, "s"))
	if err != nil {
		t.Skipf("cannot bind a unix socket here: %v", err)
	}
	// Closing the listener unlinks the node, so keep it open until cleanup.
	t.Cleanup(func() { _ = l.Close() })
	if err := os.Rename(filepath.Join(short, "s"), path); err != nil {
		t.Fatal(err)
	}
}

// KeyTree snapshots dir without the files authcore may legitimately add on a
// refused run.
func KeyTree(t testing.TB, dir string) map[string]Entry {
	t.Helper()
	m := Tree(t, dir)
	delete(m, layout.FileGitignore)
	return m
}
