package metadata

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
)

// captureLogger records what the key manager reports, so a test can assert on
// the warning rather than only on the absence of a crash.
type captureLogger struct{ warnings []string }

func (l *captureLogger) Info(string, ...any) {}

func (l *captureLogger) Warn(msg string, args ...any) {
	l.warnings = append(l.warnings, msg)
	_ = args
}

// Being unable to write the descriptor must never stop a service from
// starting: it is bookkeeping, and a read-only KeysDir — a mounted secret — is
// a supported deployment. syncMetadata therefore reports and returns instead of
// propagating, which this pins by making the write fail for real.
//
// Note the permission-bit version of this scenario is not reachable through
// New: it chmods the directory back to 0700 before writing anything, so a mode
// of 0500 does not survive. The genuine case is a filesystem that refuses the
// write, which is what a missing directory reproduces portably.
func TestSyncMetadata_writeFailureIsNotFatal(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	log := &captureLogger{}

	Sync(missing, nil, "abcdef0123456789", "", log)

	if len(log.warnings) != 1 {
		t.Fatalf("expected exactly one warning, got %d: %v", len(log.warnings), log.warnings)
	}
	if !strings.Contains(log.warnings[0], "continuing") {
		t.Errorf("the warning should say startup continues, got: %q", log.warnings[0])
	}
	if _, err := os.Stat(filepath.Join(missing, layout.FileMetadata)); !os.IsNotExist(err) {
		t.Errorf("no descriptor should exist after a failed write, stat gave: %v", err)
	}
}

// The same non-fatal handling applies to refreshing a descriptor whose key has
// been rotated underneath it.
func TestSyncMetadata_rotationWriteFailureIsNotFatal(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	log := &captureLogger{}
	existing := &Metadata{Format: CurrentFormat, Created: "2026-01-01T00:00:00Z", KeyID: "0000000000000000"}

	Sync(missing, existing, "abcdef0123456789", "", log)

	if len(log.warnings) != 1 {
		t.Fatalf("expected exactly one warning, got %d: %v", len(log.warnings), log.warnings)
	}
	if !strings.Contains(log.warnings[0], "continuing") {
		t.Errorf("the warning should say startup continues, got: %q", log.warnings[0])
	}
}

// A directory already carrying an up-to-date descriptor is left alone — no
// write, so nothing to fail.
func TestSyncMetadata_upToDateDescriptorIsNotRewritten(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	log := &captureLogger{}
	keyID := "abcdef0123456789"
	existing := &Metadata{Format: CurrentFormat, Created: "2026-01-01T00:00:00Z", KeyID: keyID, SecretBinding: "bound"}

	Sync(missing, existing, keyID, "bound", log)

	if len(log.warnings) != 0 {
		t.Errorf("an up-to-date descriptor should not be written at all, got warnings: %v", log.warnings)
	}
}

func TestWriteMetadata_renameFailsWhenDestinationIsADirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, layout.FileMetadata), 0700); err != nil {
		t.Fatal(err)
	}
	m := Metadata{Format: CurrentFormat, Created: "2026-09-19T00:00:00Z", KeyID: "0123456789abcdef"}
	err := write(dir, m)
	if err == nil {
		t.Fatal("writeMetadata succeeded with a directory at the destination")
	}
	if !strings.Contains(err.Error(), "rename") {
		t.Errorf("expected the rename failure to surface, got: %v", err)
	}
}

func TestWriteMetadata_openFailsOnReadOnlyDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits do not apply on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory write permissions")
	}

	dir := t.TempDir()
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0700) })

	m := Metadata{Format: CurrentFormat, Created: "2026-09-19T00:00:00Z", KeyID: "0123456789abcdef"}
	err := write(dir, m)
	if err == nil {
		t.Fatal("writeMetadata succeeded on a read-only directory")
	}
}
