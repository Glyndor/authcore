package generate_test

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/bootstrap/bootstraptest"
	"github.com/Glyndor/authcore/internal/keymanager/bootstrap/generate"
)

// Fresh syncs the parent of the key directory before it publishes anything. A
// parent that cannot even be opened, for a reason other than permissions, stops
// the first run instead of being waved through with a warning.
func TestFresh_unopenableParentStopsTheFirstRun(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("SyncDir is a documented no-op on Windows (a directory handle cannot be flushed), so it never reports this failure")
	}
	dir := filepath.Join(t.TempDir(), "missing-parent", "keys")
	log := &bootstraptest.Recorder{}
	_, _, _, err := generate.Fresh(dir, nil, log)
	if err == nil || !strings.Contains(err.Error(), "sync parent of keys directory") {
		t.Fatalf("Fresh with a missing parent: err = %v, want the parent-sync failure", err)
	}
	if !log.Warned("generating a fresh key set") {
		t.Errorf("the invalidation warning must come before any work: %q", log.Warns)
	}
}
