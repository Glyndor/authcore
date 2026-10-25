//go:build unix

package hostile

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
)

// Recovery must validate a staged set as a whole before it links any file of
// it into KeysDir.
func TestHostile_RecoveryRefusesAnInconsistentStagedSet(t *testing.T) {
	sb := newSandbox(t)
	mine := newSet(t)
	dir := partialWith(t, sb, mine)
	st := stage(t, dir, layout.StagingPrefix+"foreign", mine)
	foreignSet := newSet(t)
	for _, n := range []string{layout.FilePublicKey, layout.FileRefreshSecret} {
		if err := os.Remove(filepath.Join(st, n)); err != nil {
			t.Fatal(err)
		}
	}
	put(t, filepath.Join(st, layout.FilePublicKey), foreignSet.pubPEM, 0o644)
	put(t, filepath.Join(st, layout.FileRefreshSecret), foreignSet.secretHex, 0o600)

	refused(t, open(t, dir, false), mine, foreignSet)

	for _, n := range []string{layout.FilePublicKey, layout.FileRefreshSecret} {
		if _, err := os.Lstat(filepath.Join(dir, n)); err == nil {
			t.Errorf("%s from an inconsistent staging directory was linked into KeysDir", n)
		}
	}
}
