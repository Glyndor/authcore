package generate_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/bootstrap/bootstraptest"
	"github.com/Glyndor/authcore/internal/keymanager/layout"
)

func TestNoHardLinksRefusesWithoutPublishing(t *testing.T) {
	bootstraptest.WithLinkFile(t, func(_, _ string) error {
		return errors.New("ENOTSUP simulation: filesystem refuses hard links")
	})

	dir := t.TempDir()
	_, err := bootstraptest.New(dir, bootstraptest.SilentLog{})
	if err == nil {
		t.Fatal("New succeeded on a filesystem without hard links")
	}
	if !strings.Contains(err.Error(), "hard links") {
		t.Errorf("error must mention 'hard links', got: %v", err)
	}
	if !strings.Contains(err.Error(), "KeyStore") {
		t.Errorf("error must mention KeyStore, got: %v", err)
	}
	for _, name := range layout.KeyFileNames() {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Errorf("%s should not exist: %v", name, err)
		}
	}
	if list := bootstraptest.ListStagingDirs(t, dir); len(list) != 0 {
		t.Errorf("staging dirs must be cleaned up, got %v", list)
	}
}

func TestPartialSetWithoutStagingIsRefusedWithSafeAdvice(t *testing.T) {
	dir := t.TempDir()
	if _, err := bootstraptest.New(dir, bootstraptest.SilentLog{}); err != nil {
		t.Fatalf("seed New: %v", err)
	}
	before := bootstraptest.ReadSet(t, dir)
	if err := os.Remove(filepath.Join(dir, layout.FileRefreshSecret)); err != nil {
		t.Fatalf("remove refresh secret: %v", err)
	}

	_, err := bootstraptest.New(dir, bootstraptest.SilentLog{})
	if err == nil {
		t.Fatal("New succeeded with a partial set and no staging dir")
	}
	msg := err.Error()
	if !strings.Contains(msg, "restore") {
		t.Errorf("error must mention 'restore', got: %v", err)
	}
	if !strings.Contains(msg, layout.FileRefreshSecret) {
		t.Errorf("error must name %s, got: %v", layout.FileRefreshSecret, err)
	}
	if strings.Contains(msg, "delete all key files") {
		t.Errorf("error must NOT recommend 'delete all key files', got: %v", err)
	}

	after := bootstraptest.ReadPublishedSet(t, dir)
	if !bytes.Equal(before[0], after[0]) {
		t.Error("private key bytes changed across the refused restart")
	}
	if _, err := os.Stat(filepath.Join(dir, layout.FileRefreshSecret)); !os.IsNotExist(err) {
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
	if _, err := bootstraptest.New(outside, bootstraptest.SilentLog{}); err != nil {
		t.Fatalf("seed outside: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, ".staging-deadbeefdeadbeef")); err != nil {
		t.Fatal(err)
	}
	privBytes, err := os.ReadFile(filepath.Join(outside, layout.FilePrivateKey)) // #nosec G304 -- test fixture
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, layout.FilePrivateKey), privBytes, 0600); err != nil {
		t.Fatal(err)
	}

	_, err = bootstraptest.New(dir, bootstraptest.SilentLog{})
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
	if _, err := bootstraptest.New(ownerA, bootstraptest.SilentLog{}); err != nil {
		t.Fatalf("seed ownerA: %v", err)
	}
	for _, name := range layout.KeyFileNames() {
		bootstraptest.CopyFile(t, filepath.Join(ownerA, name), filepath.Join(stagingA, name))
	}

	ownerB := filepath.Join(base, "ownerB")
	if _, err := bootstraptest.New(ownerB, bootstraptest.SilentLog{}); err != nil {
		t.Fatalf("seed ownerB: %v", err)
	}
	bootstraptest.CopyFile(t, filepath.Join(stagingA, layout.FilePrivateKey), filepath.Join(dir, layout.FilePrivateKey))
	bootstraptest.CopyFile(t, filepath.Join(ownerB, layout.FilePublicKey), filepath.Join(dir, layout.FilePublicKey))

	_, err := bootstraptest.New(dir, bootstraptest.SilentLog{})
	if err == nil {
		t.Fatal("New succeeded despite the published public key differing from staging")
	}
	if !strings.Contains(err.Error(), layout.FilePublicKey) {
		t.Errorf("error must name %s, got: %v", layout.FilePublicKey, err)
	}
	for _, name := range []string{layout.FilePrivateKey, layout.FilePublicKey} {
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
	if _, err := bootstraptest.New(ownerA, bootstraptest.SilentLog{}); err != nil {
		t.Fatalf("seed ownerA: %v", err)
	}
	for _, name := range layout.KeyFileNames() {
		bootstraptest.CopyFile(t, filepath.Join(ownerA, name), filepath.Join(stagingA, name))
	}

	ownerB := filepath.Join(base, "ownerB")
	if _, err := bootstraptest.New(ownerB, bootstraptest.SilentLog{}); err != nil {
		t.Fatalf("seed ownerB: %v", err)
	}

	bootstraptest.CopyFile(t, filepath.Join(stagingA, layout.FilePrivateKey), filepath.Join(dir, layout.FilePrivateKey))
	bootstraptest.CopyFile(t, filepath.Join(ownerB, layout.FileRefreshSecret), filepath.Join(dir, layout.FileRefreshSecret))

	_, err := bootstraptest.New(dir, bootstraptest.SilentLog{})
	if err == nil {
		t.Fatal("New succeeded with a mixed refresh secret")
	}
	if !strings.Contains(err.Error(), layout.FileRefreshSecret) {
		t.Errorf("error must name %s, got: %v", layout.FileRefreshSecret, err)
	}
	if _, err := os.Stat(filepath.Join(dir, layout.FilePublicKey)); !os.IsNotExist(err) {
		t.Errorf("public key must not be linked, stat gave: %v", err)
	}
	for _, name := range []string{layout.FilePrivateKey, layout.FileRefreshSecret} {
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
	if _, err := bootstraptest.New(ownerDir, bootstraptest.SilentLog{}); err != nil {
		t.Fatalf("seed owner: %v", err)
	}
	for _, name := range layout.KeyFileNames() {
		bootstraptest.CopyFile(t, filepath.Join(ownerDir, name), filepath.Join(staging, name))
		bootstraptest.CopyFile(t, filepath.Join(ownerDir, name), filepath.Join(dir, name))
	}
	if err := os.Remove(filepath.Join(dir, layout.FileRefreshSecret)); err != nil {
		t.Fatal(err)
	}
	missingBytes, err := os.ReadFile(filepath.Join(ownerDir, layout.FileRefreshSecret)) // #nosec G304 -- test fixture
	if err != nil {
		t.Fatal(err)
	}

	var fired atomic.Bool
	bootstraptest.WithLinkFile(t, func(oldpath, newpath string) error {
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

	km, err := bootstraptest.New(dir, bootstraptest.SilentLog{})
	if err != nil {
		t.Fatalf("helper New: %v", err)
	}
	for _, name := range layout.KeyFileNames() {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s missing after helper New: %v", name, err)
		}
	}
	wantRefresh := bootstraptest.MustHexDecode(t, missingBytes)
	if !bytes.Equal(km.RefreshSecret(), wantRefresh) {
		t.Errorf("helper loaded a different refresh secret")
	}
}
