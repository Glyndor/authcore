package keyload

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

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
	want := writeSet(t, dir)
	before := listing(t, dir)

	priv, pub, secret, err := LoadOnly(dir, silentLog{})
	if err != nil {
		t.Fatalf("LoadOnly: %v", err)
	}
	if !priv.Equal(want.priv) || !pub.Equal(want.pub) || string(secret) != string(want.secret) {
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
	writeSet(t, dir)
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0700) })

	if _, _, _, err := LoadOnly(dir, silentLog{}); err != nil {
		t.Fatalf("LoadOnly on a 0500 directory: %v", err)
	}
}

func TestLoadOnly_missingDirectoryNamesLoadOnlyMode(t *testing.T) {
	_, _, _, err := LoadOnly(filepath.Join(t.TempDir(), "absent"), silentLog{})
	if err == nil || !strings.Contains(err.Error(), "load-only mode") || !strings.Contains(err.Error(), layout.FileRefreshSecret) {
		t.Fatalf("LoadOnly = %v, want the missing-directory advice", err)
	}
}

func TestLoadOnly_aFileWhereTheDirectoryShouldBeIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys")
	if err := os.WriteFile(path, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	_, _, _, err := LoadOnly(path, silentLog{})
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
	_, _, _, err := LoadOnly(filepath.Join(file, "keys"), silentLog{})
	if err == nil || !strings.Contains(err.Error(), "inspect key directory") {
		t.Fatalf("LoadOnly = %v, want the inspect failure", err)
	}
}

func TestLoadOnly_corruptDescriptorIsRefused(t *testing.T) {
	dir := t.TempDir()
	writeSet(t, dir)
	put(t, dir, layout.FileMetadata, nil, 0600)
	_, _, _, err := LoadOnly(dir, silentLog{})
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
			writeSet(t, dir)
			for _, f := range remove {
				if err := os.Remove(filepath.Join(dir, f)); err != nil {
					t.Fatal(err)
				}
			}
			before := listing(t, dir)

			_, _, _, err := LoadOnly(dir, silentLog{})
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
	writeSet(t, dir)
	loop := filepath.Join(dir, layout.FilePublicKey)
	if err := os.Remove(loop); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(loop, loop); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := LoadOnly(dir, silentLog{}); err == nil || !strings.Contains(err.Error(), "inspecting") {
		t.Fatalf("LoadOnly = %v, want the classification error", err)
	}
}

func TestLoadOnly_malformedKeyMaterialIsPropagated(t *testing.T) {
	dir := t.TempDir()
	writeSet(t, dir)
	put(t, dir, layout.FileRefreshSecret, []byte("not hex\n"), 0600)
	_, _, _, err := LoadOnly(dir, silentLog{})
	if err == nil || !strings.Contains(err.Error(), "refresh secret") {
		t.Fatalf("LoadOnly = %v, want the refresh-secret refusal", err)
	}
}

func TestLoadOnly_warnsWhenTheKeysDirectoryIsWritableByOthers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits do not apply on Windows")
	}
	dir := t.TempDir()
	writeSet(t, dir)
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	log := &recorder{}
	if _, _, _, err := LoadOnly(dir, log); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, w := range log.warnings {
		if strings.Contains(w, "key directory") && strings.Contains(w, "writable by group or others") {
			found = true
		}
	}
	if !found {
		t.Errorf("no warning about the writable directory: %q", log.warnings)
	}
}

func TestLoadOnly_reportsLeftoverStagingDirectories(t *testing.T) {
	dir := t.TempDir()
	writeSet(t, dir)
	if err := os.Mkdir(filepath.Join(dir, layout.StagingPrefix+"deadbeefdeadbeef"), 0700); err != nil {
		t.Fatal(err)
	}
	log := &recorder{}
	if _, _, _, err := LoadOnly(dir, log); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, w := range log.warnings {
		if strings.Contains(w, "can be deleted") {
			found = true
		}
	}
	if !found {
		t.Errorf("no leftover warning: %q", log.warnings)
	}
}
