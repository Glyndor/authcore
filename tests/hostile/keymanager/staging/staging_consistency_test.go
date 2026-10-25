//go:build unix

package staging

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/tests/hostile/keymanager/hostiletest"
)

// Recovery must validate a staged set as a whole before it links any file of
// it into KeysDir.
func TestHostile_RecoveryRefusesAnInconsistentStagedSet(t *testing.T) {
	sb := hostiletest.NewSandbox(t)
	mine := hostiletest.NewSet(t)
	dir := partialWith(t, sb, mine)
	st := stage(t, dir, layout.StagingPrefix+"foreign", mine)
	foreignSet := hostiletest.NewSet(t)
	for _, n := range []string{layout.FilePublicKey, layout.FileRefreshSecret} {
		if err := os.Remove(filepath.Join(st, n)); err != nil {
			t.Fatal(err)
		}
	}
	hostiletest.Put(t, filepath.Join(st, layout.FilePublicKey), foreignSet.PubPEM, 0o644)
	hostiletest.Put(t, filepath.Join(st, layout.FileRefreshSecret), foreignSet.SecretHex, 0o600)

	hostiletest.Refused(t, hostiletest.Open(t, dir, false), mine, foreignSet)

	for _, n := range []string{layout.FilePublicKey, layout.FileRefreshSecret} {
		if _, err := os.Lstat(filepath.Join(dir, n)); err == nil {
			t.Errorf("%s from an inconsistent staging directory was linked into KeysDir", n)
		}
	}
}
