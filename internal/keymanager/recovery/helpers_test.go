package recovery

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/recovery/recoverytest"
	"github.com/Glyndor/authcore/internal/keymanager/seams"
)

type silentLog = recoverytest.SilentLog

var copyFile = recoverytest.CopyFile

// seedKeys stands in for a published key set; see recoverytest.SeedKeys. The
// first result exists only so call sites read like the constructor they
// replace.
func seedKeys(dir string, _ layout.Logger) (struct{}, error) {
	return struct{}{}, recoverytest.SeedKeys(dir)
}

func listStagingDirs(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir) // #nosec G304 -- test fixture
	if err != nil {
		t.Fatalf("readdir %s: %v", dir, err)
	}
	var out []string
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), layout.StagingPrefix) {
			continue
		}
		lst, err := os.Lstat(filepath.Join(dir, e.Name())) // #nosec G304 -- test fixture
		if err != nil || !lst.IsDir() || lst.Mode()&os.ModeSymlink != 0 {
			continue
		}
		out = append(out, e.Name())
	}
	return out
}

func withLinkFile(t *testing.T, fn func(string, string) error) {
	t.Helper()
	prev := seams.LinkFile
	seams.LinkFile = fn
	t.Cleanup(func() { seams.LinkFile = prev })
}
