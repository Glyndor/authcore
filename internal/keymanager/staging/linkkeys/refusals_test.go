package linkkeys

import (
	"errors"
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

func TestLinkKeys_noHardLinksRefusesAfterPrivateWasPublished(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hard links require POSIX semantics")
	}

	// Pre-populate the staging dir and let Link succeed for the
	// private key link, then fail with a non-ErrExist error for the
	// public key. The private key is already published, so the staging
	// directory must be kept as recovery material.
	dir := t.TempDir()
	staging := filepath.Join(dir, ".staging-aaaaaaaaaaaaaaaaaaaa")
	if err := os.MkdirAll(staging, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range layout.KeyFileNames() {
		if err := os.WriteFile(filepath.Join(staging, name), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}

	var fired int32
	stagingtest.WithLinkFile(t, func(oldpath, newpath string) error {
		n := atomic.AddInt32(&fired, 1)
		if n == 1 {
			return os.Link(oldpath, newpath)
		}
		return errors.New("ENOTSUP simulation")
	})

	err := Link(dir, staging, stagingtest.SilentLog{})
	if err == nil {
		t.Fatal("Link succeeded despite the second link failing")
	}
	if !strings.Contains(err.Error(), "hard links") {
		t.Errorf("error must mention 'hard links', got: %v", err)
	}
	if !strings.Contains(err.Error(), "staging") {
		t.Errorf("error must mention the staging directory, got: %v", err)
	}
	if _, err := os.Stat(staging); err != nil {
		t.Errorf("staging directory was removed: %v", err)
	}
}

func TestLinkKeys_nonExistErrorBeforePrivatePublished(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hard links require POSIX semantics")
	}

	dir := t.TempDir()
	staging := filepath.Join(dir, ".staging-aaaaaaaaaaaaaaaaaaaa")
	if err := os.MkdirAll(staging, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range layout.KeyFileNames() {
		if err := os.WriteFile(filepath.Join(staging, name), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	stagingtest.WithLinkFile(t, func(_, _ string) error {
		return errors.New("ENOTSUP simulation")
	})

	err := Link(dir, staging, stagingtest.SilentLog{})
	if err == nil {
		t.Fatal("Link succeeded despite the first link failing")
	}
	if !strings.Contains(err.Error(), "hard links") {
		t.Errorf("error must mention 'hard links', got: %v", err)
	}
	if !strings.Contains(err.Error(), "KeyStore") {
		t.Errorf("error must mention KeyStore, got: %v", err)
	}
	if _, err := os.Stat(staging); !os.IsNotExist(err) {
		t.Errorf("staging directory was kept: stat gave: %v", err)
	}
}

func TestLinkKeys_symlinkOnPublicLinkRefusesAndKeepsStaging(t *testing.T) {
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
	if err := os.WriteFile(filepath.Join(dir, layout.FilePrivateKey), []byte("already"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(staging, layout.FilePrivateKey), filepath.Join(dir, layout.FilePublicKey)); err != nil {
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
		t.Fatal("Link succeeded when the public slot was a symlink")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("error must mention symlink, got: %v", err)
	}
	if _, err := os.Stat(staging); err != nil {
		t.Errorf("staging directory was removed: %v", err)
	}
}

func TestLinkKeys_symlinkOnSecretLinkRefusesAndKeepsStaging(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on Windows")
	}

	dir := t.TempDir()
	staging := filepath.Join(dir, ".staging-cccccccccccccccccccc")
	if err := os.MkdirAll(staging, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range layout.KeyFileNames() {
		if err := os.WriteFile(filepath.Join(staging, name), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, layout.FilePrivateKey), []byte("a"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, layout.FilePublicKey), []byte("b"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(staging, layout.FilePrivateKey), filepath.Join(dir, layout.FileRefreshSecret)); err != nil {
		t.Fatal(err)
	}

	var fired int32
	stagingtest.WithLinkFile(t, func(_, _ string) error {
		if atomic.AddInt32(&fired, 1) <= 2 {
			return nil
		}
		return fs.ErrExist
	})

	err := Link(dir, staging, stagingtest.SilentLog{})
	if err == nil {
		t.Fatal("Link succeeded when the secret slot was a symlink")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("error must mention symlink, got: %v", err)
	}
	if _, err := os.Stat(staging); err != nil {
		t.Errorf("staging directory was removed: %v", err)
	}
}

// Link' "concurrent link holds bytes from a different initialisation"
// branch. The published public key already exists at the destination from
// a second initialiser; the bytes do not match our staged copy. Link
// refuses with the shared two-init error, the same refusal the recovery
// path uses on a different-bytes slot.
func TestLinkKeys_concurrentLinkHoldsForeignBytes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hard links require POSIX semantics")
	}

	dir := t.TempDir()
	staging := filepath.Join(dir, ".staging-bbbbbbbbbbbbbbbbbbbb")
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
	if err := os.WriteFile(filepath.Join(dir, layout.FilePublicKey), []byte("exist-pub-"), 0644); err != nil {
		t.Fatal(err)
	}

	var fired int32
	stagingtest.WithLinkFile(t, func(oldpath, newpath string) error {
		if atomic.AddInt32(&fired, 1) == 1 {
			return nil
		}
		return fs.ErrExist
	})

	err := Link(dir, staging, stagingtest.SilentLog{})
	if err == nil {
		t.Fatal("Link succeeded despite a byte mismatch on the public key")
	}
	if !strings.Contains(err.Error(), "two different initialisations") {
		t.Errorf("error must be the two-init error, got: %v", err)
	}
}
