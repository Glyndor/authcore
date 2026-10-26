package metadata_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/metadata"
	"github.com/Glyndor/authcore/internal/keymanager/seams"
)

type capture struct {
	mu          sync.Mutex
	infos, warn []string
}

func (c *capture) Info(msg string, args ...any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.infos = append(c.infos, fmt.Sprintf(msg, args...))
}

func (c *capture) Warn(msg string, args ...any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.warn = append(c.warn, fmt.Sprintf(msg, args...))
}

func contains(lines []string, fragment string) bool {
	for _, l := range lines {
		if strings.Contains(l, fragment) {
			return true
		}
	}
	return false
}

func TestSync_RecordsFormatOneAndSaysSo(t *testing.T) {
	if metadata.CurrentFormat != 1 {
		t.Fatalf("CurrentFormat = %d: bumping it changes what older releases read, and needs a migration", metadata.CurrentFormat)
	}
	dir := t.TempDir()
	var log capture

	if err := metadata.Sync(dir, nil, "kid-1", "bind-1", &log); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(filepath.Join(dir, layout.FileMetadata))
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Format        int    `json:"format"`
		KeyID         string `json:"key_id"`
		SecretBinding string `json:"secret_binding"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got.Format != 1 || got.KeyID != "kid-1" || got.SecretBinding != "bind-1" {
		t.Fatalf("metadata.json = %s", raw)
	}
	if want := fmt.Sprintf("recorded on-disk format 1 for %s", dir); !contains(log.infos, want) {
		t.Errorf("infos = %q, want one containing %q", log.infos, want)
	}
	if len(log.warn) != 0 {
		t.Errorf("unexpected warnings: %q", log.warn)
	}
}

func TestSync_ReportsWhatItChanged(t *testing.T) {
	t.Run("rotated key", func(t *testing.T) {
		dir := t.TempDir()
		var log capture
		old := &metadata.Metadata{Format: 1, KeyID: "old", SecretBinding: "bind"}
		if err := metadata.Sync(dir, old, "new", "bind-2", &log); err != nil {
			t.Fatal(err)
		}
		if !contains(log.infos, "signing key changed") || !contains(log.infos, "key id new") {
			t.Errorf("infos = %q", log.infos)
		}
		got, err := metadata.Read(dir)
		if err != nil || got.KeyID != "new" || got.SecretBinding != "bind-2" {
			t.Fatalf("Read = %+v, %v", got, err)
		}
	})
	t.Run("binding added to an older descriptor", func(t *testing.T) {
		dir := t.TempDir()
		var log capture
		old := &metadata.Metadata{Format: 1, KeyID: "same"}
		if err := metadata.Sync(dir, old, "same", "bind", &log); err != nil {
			t.Fatal(err)
		}
		if !contains(log.infos, "recorded the refresh secret binding") {
			t.Errorf("infos = %q", log.infos)
		}
	})
	t.Run("nothing to do", func(t *testing.T) {
		dir := t.TempDir()
		var log capture
		cur := &metadata.Metadata{Format: 1, KeyID: "same", SecretBinding: "bind"}
		if err := metadata.Sync(dir, cur, "same", "bind", &log); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(dir, layout.FileMetadata)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("an up-to-date descriptor was rewritten: %v", err)
		}
		if len(log.infos)+len(log.warn) != 0 {
			t.Errorf("logged %q %q", log.infos, log.warn)
		}
	})
}

// A write that stops before the rename leaves its temp file behind, named with
// eight random bytes in hex.
func TestSync_TempFileNameCarriesSixteenHexDigits(t *testing.T) {
	dir := t.TempDir()
	prev := seams.FaultAt
	seams.FaultAt = func(point string) error {
		if point == "metadata-before-rename" {
			return errors.New("stop before the rename")
		}
		return nil
	}
	t.Cleanup(func() { seams.FaultAt = prev })
	var log capture

	if err := metadata.Sync(dir, nil, "kid", "bind", &log); err != nil {
		t.Fatal(err)
	}

	left, err := filepath.Glob(filepath.Join(dir, ".metadata.json.tmp-*"))
	if err != nil || len(left) != 1 {
		t.Fatalf("temp files = %v, %v; want exactly one", left, err)
	}
	if !regexp.MustCompile(`\.tmp-[0-9a-f]{16}$`).MatchString(left[0]) {
		t.Errorf("temp file %s does not end in 16 hex digits", left[0])
	}
	if _, err := os.Stat(filepath.Join(dir, layout.FileMetadata)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("metadata.json exists although the rename never happened: %v", err)
	}
	if !contains(log.warn, "stop before the rename") {
		t.Errorf("warnings = %q", log.warn)
	}
}

// The directory is synced after the rename; when that fails the write is
// reported (as a warning, by design), not swallowed.
func TestSync_ReportsAFailedDirectorySyncAfterTheRename(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("SyncDir is a documented no-op on Windows (a directory handle cannot be flushed), so it never reports this failure")
	}
	if os.Getuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	dir := t.TempDir()
	// Write and search without read: the rename works, opening the directory
	// to sync it does not.
	if err := os.Chmod(dir, 0o300); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	var log capture

	if err := metadata.Sync(dir, nil, "kid", "bind", &log); err != nil {
		t.Fatal(err)
	}
	if !contains(log.warn, "sync keys directory after metadata rename") {
		t.Fatalf("warnings = %q, want the failed directory sync", log.warn)
	}
}

func TestSync_WritesAFileThatEndsWithANewline(t *testing.T) {
	dir := t.TempDir()
	if err := metadata.Sync(dir, nil, "kid", "bind", &capture{}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, layout.FileMetadata))
	if err != nil || !strings.HasSuffix(string(raw), "}\n") {
		t.Fatalf("metadata.json = %q, %v; want it to end with a newline", raw, err)
	}
}

// A directory that cannot take the temp file is reported as that, not as a
// failed rename of a file that was never written.
func TestSync_ReportsAnUnwritableDirectoryAsAFailedWrite(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no Unix permission bits: Chmod only toggles read-only and Stat reports a synthetic mode, so a directory cannot be made unwritable this way")
	}
	if os.Getuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	var log capture

	if err := metadata.Sync(dir, nil, "kid", "bind", &log); err != nil {
		t.Fatal(err)
	}
	if !contains(log.warn, "write metadata temp") || contains(log.warn, "rename metadata temp") {
		t.Fatalf("warnings = %q, want the failed temp write only", log.warn)
	}
}
