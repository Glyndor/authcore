package recovery

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/recovery/recoverytest"
)

// A staging directory that disagrees with the published files keeps refusing,
// call after call, until an operator resolves it.
func TestRefuseConflictIsStickyAndNamesTheFile(t *testing.T) {
	recoverytest.PosixOnly(t)
	dir := recoverytest.MustSeed(t, t.TempDir())
	recoverytest.StagingFrom(t, dir, "copy", dir)
	if err := RefuseConflict(dir); err != nil {
		t.Fatalf("a staging copy of the published set is not a conflict: %v", err)
	}

	other := recoverytest.MustSeed(t, t.TempDir())
	recoverytest.CopyFile(t, filepath.Join(other, layout.FileRefreshSecret), filepath.Join(dir, layout.FileRefreshSecret))
	for i := 0; i < 2; i++ {
		err := RefuseConflict(dir)
		if err == nil || !strings.Contains(err.Error(), layout.FileRefreshSecret) {
			t.Fatalf("call %d: err = %v", i, err)
		}
	}
}
