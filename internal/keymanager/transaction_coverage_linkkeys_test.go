package keymanager

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
)

// Coverage tests for linkKeys: hard-link refusal before and after the
// private key is published, symlink refusal on the second and third
// link, the bytes.Equal length-mismatch and loop-mismatch negative
// branches, and the non-ErrExist error from the first link.

func TestLinkKeys_noHardLinksRefusesAfterPrivateWasPublished(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hard links require POSIX semantics")
	}

	// Pre-populate the staging dir and let linkKeys succeed for the
	// private key link, then fail with a non-ErrExist error for the
	// public key. The private key is already published, so the staging
	// directory must be kept as recovery material.
	dir := t.TempDir()
	staging := filepath.Join(dir, ".staging-aaaaaaaaaaaaaaaaaaaa")
	if err := os.MkdirAll(staging, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{filePrivateKey, filePublicKey, fileRefreshSecret} {
		if err := os.WriteFile(filepath.Join(staging, name), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}

	var fired int32
	withLinkFile(t, func(oldpath, newpath string) error {
		n := atomic.AddInt32(&fired, 1)
		if n == 1 {
			return os.Link(oldpath, newpath)
		}
		return errors.New("ENOTSUP simulation")
	})

	err := linkKeys(dir, staging, silentLog{})
	if err == nil {
		t.Fatal("linkKeys succeeded despite the second link failing")
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
	for _, name := range []string{filePrivateKey, filePublicKey, fileRefreshSecret} {
		if err := os.WriteFile(filepath.Join(staging, name), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	withLinkFile(t, func(_, _ string) error {
		return errors.New("ENOTSUP simulation")
	})

	err := linkKeys(dir, staging, silentLog{})
	if err == nil {
		t.Fatal("linkKeys succeeded despite the first link failing")
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
	for _, name := range []string{filePrivateKey, filePublicKey, fileRefreshSecret} {
		if err := os.WriteFile(filepath.Join(staging, name), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, filePrivateKey), []byte("already"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(staging, filePrivateKey), filepath.Join(dir, filePublicKey)); err != nil {
		t.Fatal(err)
	}

	var fired int32
	withLinkFile(t, func(_, _ string) error {
		if atomic.AddInt32(&fired, 1) == 1 {
			return nil
		}
		return fs.ErrExist
	})

	err := linkKeys(dir, staging, silentLog{})
	if err == nil {
		t.Fatal("linkKeys succeeded when the public slot was a symlink")
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
	for _, name := range []string{filePrivateKey, filePublicKey, fileRefreshSecret} {
		if err := os.WriteFile(filepath.Join(staging, name), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, filePrivateKey), []byte("a"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, filePublicKey), []byte("b"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(staging, filePrivateKey), filepath.Join(dir, fileRefreshSecret)); err != nil {
		t.Fatal(err)
	}

	var fired int32
	withLinkFile(t, func(_, _ string) error {
		if atomic.AddInt32(&fired, 1) <= 2 {
			return nil
		}
		return fs.ErrExist
	})

	err := linkKeys(dir, staging, silentLog{})
	if err == nil {
		t.Fatal("linkKeys succeeded when the secret slot was a symlink")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("error must mention symlink, got: %v", err)
	}
	if _, err := os.Stat(staging); err != nil {
		t.Errorf("staging directory was removed: %v", err)
	}
}

// linkKeys' "concurrent link holds bytes from a different initialisation"
// branch. The published public key already exists at the destination from
// a second initialiser; the bytes do not match our staged copy. linkKeys
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
	if err := os.WriteFile(filepath.Join(staging, filePrivateKey), []byte("priv"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staging, filePublicKey), []byte("staged-pub"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staging, fileRefreshSecret), []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, filePublicKey), []byte("exist-pub-"), 0644); err != nil {
		t.Fatal(err)
	}

	var fired int32
	withLinkFile(t, func(oldpath, newpath string) error {
		if atomic.AddInt32(&fired, 1) == 1 {
			return nil
		}
		return fs.ErrExist
	})

	err := linkKeys(dir, staging, silentLog{})
	if err == nil {
		t.Fatal("linkKeys succeeded despite a byte mismatch on the public key")
	}
	if !strings.Contains(err.Error(), "two different initialisations") {
		t.Errorf("error must be the two-init error, got: %v", err)
	}
}
