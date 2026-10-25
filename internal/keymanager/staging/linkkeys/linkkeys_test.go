package linkkeys

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/staging/stagingtest"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
)

// Link' second-or-third slot refuses on a different-bytes concurrent
// link. Before the fix this path also called os.RemoveAll(staging); after the
// fix the staging directory is kept so the refused transaction leaves
// recovery material behind, and the error text is the shared two-init error
// the recovery path uses.
func TestLinkKeysKeepsStagingWhenAPublishedSlotDiffers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hard links require POSIX semantics")
	}

	dir := t.TempDir()
	staging := filepath.Join(dir, ".staging-aaaaaaaaaaaaaaaaaaaa")
	if err := os.MkdirAll(staging, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staging, layout.FilePrivateKey), []byte("priv"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staging, layout.FilePublicKey), []byte("staged-pub"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staging, layout.FileRefreshSecret), []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}

	different := []byte("exist-pub-")
	if err := os.WriteFile(filepath.Join(dir, layout.FilePublicKey), different, 0644); err != nil {
		t.Fatal(err)
	}

	var fired int32
	stagingtest.WithLinkFile(t, func(_, _ string) error {
		if atomic.AddInt32(&fired, 1) == 1 {
			return nil
		}
		return fs.ErrExist
	})

	err := Link(dir, staging, stagingtest.SilentLog{})
	if err == nil {
		t.Fatal("Link succeeded despite a byte mismatch on the public key")
	}
	if !strings.Contains(err.Error(), layout.FilePublicKey) {
		t.Errorf("error must name %s, got: %v", layout.FilePublicKey, err)
	}
	if !strings.Contains(err.Error(), "two different initialisations") {
		t.Errorf("error must be the two-init error, got: %v", err)
	}
	if _, err := os.Stat(staging); err != nil {
		t.Errorf("staging directory was removed: %v", err)
	}
}

// Link' concurrent-identical branch. A second process wrote the
// same bytes to the public key slot in KeysDir before us and reports
// fs.ErrExist; the byte compare agrees, so Link must continue and the
// directory must end up complete. Set up so the existing destination is a
// DIFFERENT inode from the staged file (otherwise linkLanded short-circuits
// to success and the bytes-equal branch is never reached).
func TestLinkKeysAcceptsIdenticalConcurrentLink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hard links require POSIX semantics")
	}

	dir := t.TempDir()
	staging := filepath.Join(dir, ".staging-bbbbbbbbbbbbbbbbbbbb")
	if err := os.MkdirAll(staging, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range layout.KeyFileNames() {
		if err := os.WriteFile(filepath.Join(staging, name), []byte("same-"+name), 0600); err != nil {
			t.Fatal(err)
		}
	}

	if err := os.WriteFile(filepath.Join(dir, layout.FilePublicKey), []byte("same-"+layout.FilePublicKey), 0644); err != nil {
		t.Fatal(err)
	}

	var fired int32
	stagingtest.WithLinkFile(t, func(oldpath, newpath string) error {
		n := atomic.AddInt32(&fired, 1)
		if n == 1 {
			return os.Link(oldpath, newpath)
		}
		if n == 2 {
			return fs.ErrExist
		}
		return os.Link(oldpath, newpath)
	})

	if err := Link(dir, staging, stagingtest.SilentLog{}); err != nil {
		t.Fatalf("Link refused an identical concurrent link: %v", err)
	}
	for _, name := range layout.KeyFileNames() {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s missing after Link: %v", name, err)
		}
	}
}

// Link's "i=0 + symlink" branch: when the first link target is a
// symlink, Link must refuse via refuseSymlinkTarget and remove the
// staging directory. Reachable in production only if the symlink preflight in New is
// bypassed (a symlink created between the preflight and Link), so the
// test drives Link directly to keep coverage of the defensive branch.
func TestLinkKeys_symlinkOnPrivateLinkRefusesAndRemovesStaging(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on Windows")
	}

	dir := t.TempDir()
	staging := filepath.Join(dir, ".staging-bbbbbbbbbbbbbbbbbbbb")
	if err := os.MkdirAll(staging, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range layout.KeyFileNames() {
		if err := os.WriteFile(filepath.Join(staging, name), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(staging, layout.FilePrivateKey), filepath.Join(dir, layout.FilePrivateKey)); err != nil {
		t.Fatal(err)
	}

	stagingtest.WithLinkFile(t, func(_, _ string) error {
		return fs.ErrExist
	})

	err := Link(dir, staging, stagingtest.SilentLog{})
	if err == nil {
		t.Fatal("Link succeeded when the private slot was a symlink")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("error must mention symlink, got: %v", err)
	}
	if _, err := os.Stat(staging); !os.IsNotExist(err) {
		t.Errorf("staging directory was kept on i=0 symlink refusal: stat gave %v", err)
	}
}

// Link's "read existing after ErrExist failed for a non-ErrNotExist
// reason" branch. A pre-existing destination that is too big for the capped
// reader makes readCapped fail; Link must surface it rather than try to
// compare oversized bytes.
func TestLinkKeys_readExistingFailureIsSurfaced(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hard links require POSIX semantics")
	}

	dir := t.TempDir()
	staging := filepath.Join(dir, ".staging-eeee5555666677778888")
	if err := os.MkdirAll(staging, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staging, layout.FilePrivateKey), []byte("priv"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staging, layout.FilePublicKey), []byte("pub"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staging, layout.FileRefreshSecret), []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	oversized := make([]byte, layout.MaxKeyFileSize+1)
	for i := range oversized {
		oversized[i] = 'A'
	}
	if err := os.WriteFile(filepath.Join(dir, layout.FilePublicKey), oversized, 0644); err != nil {
		t.Fatal(err)
	}

	var fired int32
	stagingtest.WithLinkFile(t, func(oldpath, newpath string) error {
		if atomic.AddInt32(&fired, 1) == 1 {
			return os.Link(oldpath, newpath)
		}
		return fs.ErrExist
	})

	err := Link(dir, staging, stagingtest.SilentLog{})
	if err == nil {
		t.Fatal("Link succeeded despite an oversized existing public key")
	}
	if !strings.Contains(err.Error(), "read existing") {
		t.Errorf("error must come from readCapped on the existing file, got: %v", err)
	}
	if _, err := os.Stat(filepath.Join(staging, layout.FilePrivateKey)); err != nil {
		t.Errorf("staging directory was removed despite partial publish: %v", err)
	}
}

// Link' "lstat destination after ErrExist" branch. A wrapper linkFile
// pre-creates the destination file, then deletes it, then returns
// fs.ErrExist. linkLanded finds nothing there (returns false), errors.Is
// matches ErrExist, and Lstat(dst) fails because the destination is gone.
// Link must surface the lstat error rather than misclassifying it as a
// wait-and-load condition.
func TestLinkKeys_lstatDestinationFailureIsSurfaced(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hard links require POSIX semantics")
	}

	dir := t.TempDir()
	staging := filepath.Join(dir, ".staging-33333333333333333333")
	if err := os.MkdirAll(staging, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staging, layout.FilePrivateKey), []byte("priv"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{layout.FilePublicKey, layout.FileRefreshSecret} {
		if err := os.WriteFile(filepath.Join(staging, name), []byte(name), 0600); err != nil {
			t.Fatal(err)
		}
	}

	stagingtest.WithLinkFile(t, func(_, newpath string) error {
		f, err := os.Create(newpath)
		if err != nil {
			return err
		}
		_ = f.Close()
		if err := os.Remove(newpath); err != nil {
			return err
		}
		return fs.ErrExist
	})

	err := Link(dir, staging, stagingtest.SilentLog{})
	if err == nil {
		t.Fatal("Link succeeded despite lstat failing on the destination")
	}
	if !strings.Contains(err.Error(), "lstat destination") {
		t.Errorf("error must come from the lstat-failure path, got: %v", err)
	}
}
