package loadonly

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/keyload/keyloadtest"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
)

// listing is a name -> size/mod-time fingerprint of a directory, to prove the
// load-only path never wrote anything.
func listing(t *testing.T, dir string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, e := range entries {
		fi, err := e.Info()
		if err != nil {
			t.Fatal(err)
		}
		out[e.Name()] = fmt.Sprintf("%s/%s/%d", fi.ModTime(), fi.Mode(), fi.Size())
	}
	return out
}

func TestLoadOnly_returnsTheKeysAndWritesNothing(t *testing.T) {
	dir := t.TempDir()
	want := keyloadtest.WriteSet(t, dir)
	before := listing(t, dir)

	priv, pub, secret, err := Load(dir, keyloadtest.SilentLog{})
	if err != nil {
		t.Fatalf("LoadOnly: %v", err)
	}
	if !priv.Equal(want.Priv) || !pub.Equal(want.Pub) || string(secret) != string(want.Secret) {
		t.Fatal("LoadOnly returned keys other than the ones on disk")
	}
	after := listing(t, dir)
	if len(after) != len(before) {
		t.Fatalf("listing changed: %v -> %v", before, after)
	}
	for name, fp := range before {
		if after[name] != fp {
			t.Errorf("%s changed", name)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, layout.FileMetadata)); !os.IsNotExist(err) {
		t.Errorf("LoadOnly created the descriptor: %v", err)
	}
}

func TestLoadOnly_loadsFromAReadOnlyDirectory(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs Unix mode bits and a non-root user")
	}
	dir := t.TempDir()
	keyloadtest.WriteSet(t, dir)
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0700) })

	if _, _, _, err := Load(dir, keyloadtest.SilentLog{}); err != nil {
		t.Fatalf("LoadOnly on a 0500 directory: %v", err)
	}
}

func TestLoadOnly_missingDirectoryNamesLoadOnlyMode(t *testing.T) {
	_, _, _, err := Load(filepath.Join(t.TempDir(), "absent"), keyloadtest.SilentLog{})
	if err == nil || !strings.Contains(err.Error(), "load-only mode") || !strings.Contains(err.Error(), layout.FileRefreshSecret) {
		t.Fatalf("LoadOnly = %v, want the missing-directory advice", err)
	}
}

func TestLoadOnly_aFileWhereTheDirectoryShouldBeIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys")
	if err := os.WriteFile(path, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	_, _, _, err := Load(path, keyloadtest.SilentLog{})
	if err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("LoadOnly = %v, want a not-a-directory refusal", err)
	}
}

func TestLoadOnly_unstattableDirectoryIsReported(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	// ENOTDIR rather than ENOENT: a path below a regular file.
	_, _, _, err := Load(filepath.Join(file, "keys"), keyloadtest.SilentLog{})
	if err == nil || !strings.Contains(err.Error(), "inspect key directory") {
		t.Fatalf("LoadOnly = %v, want the inspect failure", err)
	}
}

func TestLoadOnly_corruptDescriptorIsRefused(t *testing.T) {
	dir := t.TempDir()
	keyloadtest.WriteSet(t, dir)
	keyloadtest.Put(t, dir, layout.FileMetadata, nil, 0600)
	_, _, _, err := Load(dir, keyloadtest.SilentLog{})
	if err == nil || !strings.Contains(err.Error(), "deleting it is safe") {
		t.Fatalf("LoadOnly = %v, want the descriptor refusal with its escape", err)
	}
}

func TestLoadOnly_incompleteSetIsRefusedWithoutTouchingTheDirectory(t *testing.T) {
	for name, remove := range map[string][]string{
		"empty":   layout.KeyFileNames(),
		"partial": {layout.FileRefreshSecret},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			keyloadtest.WriteSet(t, dir)
			for _, f := range remove {
				if err := os.Remove(filepath.Join(dir, f)); err != nil {
					t.Fatal(err)
				}
			}
			before := listing(t, dir)

			_, _, _, err := Load(dir, keyloadtest.SilentLog{})
			if err == nil || !strings.Contains(err.Error(), "not complete in load-only mode") {
				t.Fatalf("LoadOnly = %v, want the incomplete refusal", err)
			}
			if strings.Contains(err.Error(), "delete all key files") {
				t.Errorf("the refusal advises deleting the key files: %v", err)
			}
			after := listing(t, dir)
			if len(after) != len(before) {
				t.Errorf("the directory was written to: %v -> %v", before, after)
			}
		})
	}
}

func TestLoadOnly_aSymlinkLoopAtAKeyNameIsReported(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink loops are POSIX-specific")
	}
	dir := t.TempDir()
	keyloadtest.WriteSet(t, dir)
	loop := filepath.Join(dir, layout.FilePublicKey)
	if err := os.Remove(loop); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(loop, loop); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := Load(dir, keyloadtest.SilentLog{}); err == nil || !strings.Contains(err.Error(), "inspecting") {
		t.Fatalf("LoadOnly = %v, want the classification error", err)
	}
}

func TestLoadOnly_malformedKeyMaterialIsPropagated(t *testing.T) {
	dir := t.TempDir()
	keyloadtest.WriteSet(t, dir)
	keyloadtest.Put(t, dir, layout.FileRefreshSecret, []byte("not hex\n"), 0600)
	_, _, _, err := Load(dir, keyloadtest.SilentLog{})
	if err == nil || !strings.Contains(err.Error(), "refresh secret") {
		t.Fatalf("LoadOnly = %v, want the refresh-secret refusal", err)
	}
}

func TestLoadOnly_warnsWhenTheKeysDirectoryIsWritableByOthers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits do not apply on Windows")
	}
	dir := t.TempDir()
	keyloadtest.WriteSet(t, dir)
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	log := &keyloadtest.Recorder{}
	if _, _, _, err := Load(dir, log); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, w := range log.Warnings {
		if strings.Contains(w, "key directory") && strings.Contains(w, "writable by group or others") {
			found = true
		}
	}
	if !found {
		t.Errorf("no warning about the writable directory: %q", log.Warnings)
	}
}

func TestLoadOnly_reportsLeftoverStagingDirectories(t *testing.T) {
	dir := t.TempDir()
	keyloadtest.WriteSet(t, dir)
	if err := os.Mkdir(filepath.Join(dir, layout.StagingPrefix+"deadbeefdeadbeef"), 0700); err != nil {
		t.Fatal(err)
	}
	log := &keyloadtest.Recorder{}
	if _, _, _, err := Load(dir, log); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, w := range log.Warnings {
		if strings.Contains(w, "can be deleted") {
			found = true
		}
	}
	if !found {
		t.Errorf("no leftover warning: %q", log.Warnings)
	}
}
