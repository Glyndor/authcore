package fileio

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWriteKeyFile_writesTheBytesWithTheRequestedMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	if err := WriteKeyFile(path, []byte("secret"), 0600); err != nil {
		t.Fatalf("WriteKeyFile: %v", err)
	}
	got, err := os.ReadFile(path) // #nosec G304 -- test fixture
	if err != nil || string(got) != "secret" {
		t.Fatalf("read back %q, %v; want %q", got, err, "secret")
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(path)
		if err != nil || fi.Mode().Perm() != 0600 {
			t.Fatalf("mode = %v, %v; want 0600", fi.Mode().Perm(), err)
		}
	}
}

func TestSyncDir_flushesAnExistingDirectory(t *testing.T) {
	if err := SyncDir(t.TempDir()); err != nil {
		t.Fatalf("SyncDir on a directory: %v", err)
	}
}

func TestReadCapped_missingFileIsReportedAsNotExist(t *testing.T) {
	_, err := ReadCapped(filepath.Join(t.TempDir(), "absent"))
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("ReadCapped(absent) = %v, want fs.ErrNotExist", err)
	}
}

func TestFileBytesIfExists_returnsTheBytesOfARegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, []byte("abc"), 0600); err != nil {
		t.Fatal(err)
	}
	data, ok, err := FileBytesIfExists(path)
	if err != nil || !ok || string(data) != "abc" {
		t.Fatalf("FileBytesIfExists = %q, %v, %v; want abc, true, nil", data, ok, err)
	}
}
