package createset

import (
	"os"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/staging/stagingtest"
)

// KeysDir that can be written and searched but not read cannot be opened for
// fsync. The staging files are written, then the sync of the parent fails and
// the failure is returned instead of being swallowed.
func TestCreateStagingSet_syncFailureOnKeysDirIsReturned(t *testing.T) {
	stagingtest.PosixOnly(t)
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory mode bits")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0300); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0700) })

	_, _, _, _, err := Create(dir)
	if err == nil || !strings.Contains(err.Error(), "sync keys directory") {
		t.Fatalf("Create = %v, want the keys-directory sync failure", err)
	}
}
