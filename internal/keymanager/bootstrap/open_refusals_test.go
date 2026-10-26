package bootstrap_test

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/bootstrap/bootstraptest"

	"github.com/Glyndor/authcore/internal/keymanager/bootstrap"
	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/material"
	"github.com/Glyndor/authcore/internal/keymanager/metadata"
)

func TestOpen_refusesToRegenerateWhenMetadataRecordsAKeySet(t *testing.T) {
	dir := t.TempDir()
	_, pub, _ := bootstraptest.OpenOK(t, dir, &bootstraptest.Recorder{})
	for _, name := range layout.KeyFileNames() {
		if err := os.Remove(filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}

	_, _, _, err := bootstrap.Open(dir, &bootstraptest.Recorder{})
	if err == nil || !strings.Contains(err.Error(), material.KeyID(pub)) || !strings.Contains(err.Error(), "none of its files remain") {
		t.Fatalf("Open = %v, want the refusal naming the recorded key id", err)
	}
	for _, name := range layout.KeyFileNames() {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Errorf("%s was regenerated: %v", name, err)
		}
	}
}

func TestOpen_refusesADirectoryFromTheFutureBeforeParsingAnything(t *testing.T) {
	dir := t.TempDir()
	future := `{"format": 99, "created": "2030-01-01T00:00:00Z", "key_id": "0123456789abcdef"}`
	if err := os.WriteFile(filepath.Join(dir, layout.FileMetadata), []byte(future), 0600); err != nil {
		t.Fatal(err)
	}
	_, _, _, err := bootstrap.Open(dir, &bootstraptest.Recorder{})
	if !errors.Is(err, metadata.ErrFormatFromFuture) {
		t.Fatalf("Open = %v, want ErrFormatFromFuture", err)
	}
	if _, err := os.Stat(filepath.Join(dir, layout.FilePrivateKey)); !os.IsNotExist(err) {
		t.Error("keys were generated into a directory written by a newer version")
	}
}

func TestOpen_refusesADanglingSymlinkBeforeGenerating(t *testing.T) {
	bootstraptest.PosixOnly(t)
	for _, name := range layout.KeyFileNames() {
		t.Run(name, func(t *testing.T) {
			base := t.TempDir()
			dir := filepath.Join(base, "keys")
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			outside := filepath.Join(base, "outside")
			if err := os.Symlink(outside, filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}
			_, _, _, err := bootstrap.Open(dir, &bootstraptest.Recorder{})
			if err == nil || !strings.Contains(err.Error(), "symlink") {
				t.Fatalf("Open = %v, want a refusal naming the symlink", err)
			}
			if _, serr := os.Stat(outside); !os.IsNotExist(serr) {
				t.Errorf("key material was written through the link: %v", serr)
			}
		})
	}
}

func TestOpen_aKeyNameThatIsADirectoryIsRefused(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, layout.FilePrivateKey), 0700); err != nil {
		t.Fatal(err)
	}
	_, _, _, err := bootstrap.Open(dir, &bootstraptest.Recorder{})
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("Open = %v, want the not-a-regular-file refusal", err)
	}
}

func TestOpen_partialSetIsRefusedWithSafeAdvice(t *testing.T) {
	dir := t.TempDir()
	bootstraptest.OpenOK(t, dir, &bootstraptest.Recorder{})
	if err := os.Remove(filepath.Join(dir, layout.FileRefreshSecret)); err != nil {
		t.Fatal(err)
	}
	_, _, _, err := bootstrap.Open(dir, &bootstraptest.Recorder{})
	if err == nil || !strings.Contains(err.Error(), "restore the missing file(s) from a backup") {
		t.Fatalf("Open = %v, want the restore advice", err)
	}
	if strings.Contains(err.Error(), "delete all key files") {
		t.Errorf("the refusal advises deleting every key file: %v", err)
	}
}

func TestOpen_unusableDirectoryPathsAreReported(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows reports a path below a regular file as not found (ERROR_PATH_NOT_FOUND) instead of not a directory, so the error this test pins cannot occur")
	}
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	// ENOTDIR from Stat, not ENOENT.
	_, _, _, err := bootstrap.Open(filepath.Join(file, "keys"), &bootstraptest.Recorder{})
	if err == nil || !strings.Contains(err.Error(), "inspect key directory") {
		t.Fatalf("path below a regular file: %v, want the inspect failure", err)
	}
}

func TestOpen_cannotCreateTheDirectoryUnderAReadOnlyParent(t *testing.T) {
	bootstraptest.NotRoot(t)
	parent := t.TempDir()
	if err := os.Chmod(parent, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0700) })
	_, _, _, err := bootstrap.Open(filepath.Join(parent, "keys"), &bootstraptest.Recorder{})
	if err == nil || !strings.Contains(err.Error(), "create key directory") {
		t.Fatalf("Open = %v, want the create failure", err)
	}
}

func TestOpen_corruptKeyMaterialIsRefusedNotRegenerated(t *testing.T) {
	dir := t.TempDir()
	bootstraptest.OpenOK(t, dir, &bootstraptest.Recorder{})
	before := bootstraptest.ReadFile(t, dir, layout.FilePrivateKey)
	if err := os.WriteFile(filepath.Join(dir, layout.FilePublicKey), []byte("junk"), 0644); err != nil {
		t.Fatal(err)
	}
	_, _, _, err := bootstrap.Open(dir, &bootstraptest.Recorder{})
	if err == nil || !strings.Contains(err.Error(), "ed25519 key pair") {
		t.Fatalf("Open = %v, want the key-pair refusal", err)
	}
	if got := bootstraptest.ReadFile(t, dir, layout.FilePrivateKey); string(got) != string(before) {
		t.Error("the private key was replaced")
	}
}
