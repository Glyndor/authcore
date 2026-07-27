package keymanager

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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

	syncMetadata(missing, nil, "abcdef0123456789", log)

	if len(log.warnings) != 1 {
		t.Fatalf("expected exactly one warning, got %d: %v", len(log.warnings), log.warnings)
	}
	if !strings.Contains(log.warnings[0], "continuing") {
		t.Errorf("the warning should say startup continues, got: %q", log.warnings[0])
	}
	if _, err := os.Stat(filepath.Join(missing, fileMetadata)); !os.IsNotExist(err) {
		t.Errorf("no descriptor should exist after a failed write, stat gave: %v", err)
	}
}

// The same non-fatal handling applies to refreshing a descriptor whose key has
// been rotated underneath it.
func TestSyncMetadata_rotationWriteFailureIsNotFatal(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	log := &captureLogger{}
	existing := &metadata{Format: currentFormat, Created: "2026-01-01T00:00:00Z", KeyID: "0000000000000000"}

	syncMetadata(missing, existing, "abcdef0123456789", log)

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
	existing := &metadata{Format: currentFormat, Created: "2026-01-01T00:00:00Z", KeyID: keyID}

	syncMetadata(missing, existing, keyID, log)

	if len(log.warnings) != 0 {
		t.Errorf("an up-to-date descriptor should not be written at all, got warnings: %v", log.warnings)
	}
}
