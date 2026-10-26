package load_test

import (
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/bootstrap/load"
	"github.com/Glyndor/authcore/internal/keymanager/keyload/keyloadtest"
	"github.com/Glyndor/authcore/internal/keymanager/metadata"
)

// Loading a healthy directory says nothing at warning level: a warning on
// every start would teach operators to ignore them.
func TestFromKeysDir_HealthyDirectoryLogsNoWarning(t *testing.T) {
	dir := t.TempDir()
	keyloadtest.WriteSet(t, dir)
	var log keyloadtest.Recorder

	if _, _, _, err := load.FromKeysDir(dir, (*metadata.Metadata)(nil), &log); err != nil {
		t.Fatal(err)
	}
	if len(log.Warnings) != 0 {
		t.Fatalf("warnings = %q, want none", log.Warnings)
	}
}
