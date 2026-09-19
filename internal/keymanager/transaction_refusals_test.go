package keymanager

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
)

// Refusal tests: a filesystem without hard links, an inconsistent partial
// set with no matching staging directory, an inconsistent slot whose bytes
// differ, and a mixed refresh secret from a different initialisation. The
// fourth case is the recovery path surviving an owner removing its staging
// mid-recovery.

func TestNoHardLinksRefusesWithoutPublishing(t *testing.T) {
	withLinkFile(t, func(_, _ string) error {
		return errors.New("ENOTSUP simulation: filesystem refuses hard links")
	})

	dir := t.TempDir()
	_, err := New(dir, silentLog{})
	if err == nil {
		t.Fatal("New succeeded on a filesystem without hard links")
	}
	if !strings.Contains(err.Error(), "hard links") {
		t.Errorf("error must mention 'hard links', got: %v", err)
	}
	if !strings.Contains(err.Error(), "KeyStore") {
		t.Errorf("error must mention KeyStore, got: %v", err)
	}
	for _, name := range []string{filePrivateKey, filePublicKey, fileRefreshSecret} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Errorf("%s should not exist: %v", name, err)
		}
	}
	if list := listStagingDirs(t, dir); len(list) != 0 {
		t.Errorf("staging dirs must be cleaned up, got %v", list)
	}
}

func TestPartialSetWithoutStagingIsRefusedWithSafeAdvice(t *testing.T) {
	dir := t.TempDir()
	if _, err := New(dir, silentLog{}); err != nil {
		t.Fatalf("seed New: %v", err)
	}
	before := readSet(t, dir)
	if err := os.Remove(filepath.Join(dir, fileRefreshSecret)); err != nil {
		t.Fatalf("remove refresh secret: %v", err)
	}

	_, err := New(dir, silentLog{})
	if err == nil {
		t.Fatal("New succeeded with a partial set and no staging dir")
	}
	msg := err.Error()
	if !strings.Contains(msg, "restore") {
		t.Errorf("error must mention 'restore', got: %v", err)
	}
	if !strings.Contains(msg, fileRefreshSecret) {
		t.Errorf("error must name %s, got: %v", fileRefreshSecret, err)
	}
	if strings.Contains(msg, "delete all key files") {
		t.Errorf("error must NOT recommend 'delete all key files', got: %v", err)
	}

	after := readPublishedSet(t, dir)
	if !bytes.Equal(before[0], after[0]) {
		t.Error("private key bytes changed across the refused restart")
	}
	if _, err := os.Stat(filepath.Join(dir, fileRefreshSecret)); !os.IsNotExist(err) {
		t.Errorf("refresh_secret.key must not be created, stat gave: %v", err)
	}
}

func TestStagingSymlinkIsIgnored(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on Windows")
	}
	base := t.TempDir()
	dir := filepath.Join(base, "keys")
	outside := filepath.Join(base, "outside")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(outside, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := New(outside, silentLog{}); err != nil {
		t.Fatalf("seed outside: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, ".staging-deadbeefdeadbeef")); err != nil {
		t.Fatal(err)
	}
	privBytes, err := os.ReadFile(filepath.Join(outside, filePrivateKey)) // #nosec G304 -- test fixture
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, filePrivateKey), privBytes, 0600); err != nil {
		t.Fatal(err)
	}

	_, err = New(dir, silentLog{})
	if err == nil {
		t.Fatal("New adopted a symlinked staging directory")
	}
	if !strings.Contains(err.Error(), "restore") {
		t.Errorf("error must recommend 'restore', got: %v", err)
	}
}

func TestDifferentBytesAtAMissingSlotIsRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hard links require POSIX semantics")
	}
	base := t.TempDir()
	dir := filepath.Join(base, "keys")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}

	ownerA := filepath.Join(base, "ownerA")
	stagingA := filepath.Join(dir, ".staging-aabbccddeeff0011")
	if err := os.MkdirAll(stagingA, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := New(ownerA, silentLog{}); err != nil {
		t.Fatalf("seed ownerA: %v", err)
	}
	for _, name := range []string{filePrivateKey, filePublicKey, fileRefreshSecret} {
		copyFile(t, filepath.Join(ownerA, name), filepath.Join(stagingA, name))
	}

	ownerB := filepath.Join(base, "ownerB")
	if _, err := New(ownerB, silentLog{}); err != nil {
		t.Fatalf("seed ownerB: %v", err)
	}
	copyFile(t, filepath.Join(stagingA, filePrivateKey), filepath.Join(dir, filePrivateKey))
	copyFile(t, filepath.Join(ownerB, filePublicKey), filepath.Join(dir, filePublicKey))

	_, err := New(dir, silentLog{})
	if err == nil {
		t.Fatal("New succeeded despite the published public key differing from staging")
	}
	if !strings.Contains(err.Error(), filePublicKey) {
		t.Errorf("error must name %s, got: %v", filePublicKey, err)
	}
	for _, name := range []string{filePrivateKey, filePublicKey} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s was removed: %v", name, err)
		}
	}
	if _, err := os.Stat(stagingA); err != nil {
		t.Errorf("staging dir was removed: %v", err)
	}
}

func TestMixedRefreshSecretIsRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hard links require POSIX semantics")
	}
	base := t.TempDir()
	dir := filepath.Join(base, "keys")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}

	ownerA := filepath.Join(base, "ownerA")
	stagingA := filepath.Join(dir, ".staging-1122334455667788")
	if err := os.MkdirAll(stagingA, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := New(ownerA, silentLog{}); err != nil {
		t.Fatalf("seed ownerA: %v", err)
	}
	for _, name := range []string{filePrivateKey, filePublicKey, fileRefreshSecret} {
		copyFile(t, filepath.Join(ownerA, name), filepath.Join(stagingA, name))
	}

	ownerB := filepath.Join(base, "ownerB")
	if _, err := New(ownerB, silentLog{}); err != nil {
		t.Fatalf("seed ownerB: %v", err)
	}

	copyFile(t, filepath.Join(stagingA, filePrivateKey), filepath.Join(dir, filePrivateKey))
	copyFile(t, filepath.Join(ownerB, fileRefreshSecret), filepath.Join(dir, fileRefreshSecret))

	_, err := New(dir, silentLog{})
	if err == nil {
		t.Fatal("New succeeded with a mixed refresh secret")
	}
	if !strings.Contains(err.Error(), fileRefreshSecret) {
		t.Errorf("error must name %s, got: %v", fileRefreshSecret, err)
	}
	if _, err := os.Stat(filepath.Join(dir, filePublicKey)); !os.IsNotExist(err) {
		t.Errorf("public key must not be linked, stat gave: %v", err)
	}
	for _, name := range []string{filePrivateKey, fileRefreshSecret} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s was removed: %v", name, err)
		}
	}
	if _, err := os.Stat(stagingA); err != nil {
		t.Errorf("staging dir was removed: %v", err)
	}
}

func TestHelperSurvivesOwnerRemovingStaging(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hard links require POSIX semantics")
	}
	base := t.TempDir()
	dir := filepath.Join(base, "keys")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(dir, ".staging-99aabbccddeeff00")
	if err := os.MkdirAll(staging, 0700); err != nil {
		t.Fatal(err)
	}

	ownerDir := filepath.Join(base, "owner")
	if _, err := New(ownerDir, silentLog{}); err != nil {
		t.Fatalf("seed owner: %v", err)
	}
	for _, name := range []string{filePrivateKey, filePublicKey, fileRefreshSecret} {
		copyFile(t, filepath.Join(ownerDir, name), filepath.Join(staging, name))
		copyFile(t, filepath.Join(ownerDir, name), filepath.Join(dir, name))
	}
	if err := os.Remove(filepath.Join(dir, fileRefreshSecret)); err != nil {
		t.Fatal(err)
	}
	missingBytes, err := os.ReadFile(filepath.Join(ownerDir, fileRefreshSecret)) // #nosec G304 -- test fixture
	if err != nil {
		t.Fatal(err)
	}

	var fired atomic.Bool
	withLinkFile(t, func(oldpath, newpath string) error {
		if filepath.Dir(oldpath) == staging && fired.CompareAndSwap(false, true) {
			if err := os.WriteFile(newpath, missingBytes, 0600); err != nil {
				return err
			}
			if err := os.RemoveAll(staging); err != nil {
				return err
			}
		}
		return os.Link(oldpath, newpath)
	})

	km, err := New(dir, silentLog{})
	if err != nil {
		t.Fatalf("helper New: %v", err)
	}
	for _, name := range []string{filePrivateKey, filePublicKey, fileRefreshSecret} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s missing after helper New: %v", name, err)
		}
	}
	wantRefresh := mustHexDecode(t, missingBytes)
	if !bytes.Equal(km.RefreshSecret(), wantRefresh) {
		t.Errorf("helper loaded a different refresh secret")
	}
}
