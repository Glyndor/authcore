package fileio

import (
	"os"
	"testing"
)

// A path that opens but cannot be read as a file surfaces the read error
// instead of an empty result: a directory opens, and reading it fails.
func TestReadCapped_unreadableEntryIsReported(t *testing.T) {
	if _, err := ReadCapped(t.TempDir()); err == nil {
		t.Fatal("ReadCapped on a directory returned no error")
	}
}

// A filesystem that cannot sync a directory is not a reason to refuse to start.
// /dev/null opens fine and answers fsync with EINVAL, the same answer some FUSE
// and network mounts give, which SyncDir reports as success.
func TestSyncDir_unsupportedSyncIsNotAnError(t *testing.T) {
	if _, err := os.Stat("/dev/null"); err != nil {
		t.Skip("/dev/null is not available")
	}
	if err := SyncDir("/dev/null"); err != nil {
		t.Fatalf("SyncDir(/dev/null) = %v, want nil", err)
	}
}
