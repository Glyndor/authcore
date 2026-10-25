package match

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/recovery/recoverytest"
)

// A key directory that cannot be listed is an error, not "no match".
func TestFindStaging_unreadableDirectoryIsSurfaced(t *testing.T) {
	got, err := FindStaging(filepath.Join(t.TempDir(), "absent"))
	if err == nil {
		t.Fatal("FindStaging succeeded on a directory that does not exist")
	}
	if got != "" {
		t.Errorf("FindStaging returned %q alongside an error", got)
	}
}

// The mirror of the oversized published key: when it is the staged private key
// that breaks the size cap, the cap error is surfaced instead of being read as
// "this staging does not match, keep looking".
func TestFindStaging_oversizedStagedPrivateKeyIsSurfaced(t *testing.T) {
	recoverytest.PosixOnly(t)
	base := t.TempDir()
	dir := recoverytest.MustSeed(t, filepath.Join(base, "keys"))
	staging := recoverytest.StagingFrom(t, dir, "aaaa0000bbbb1111", dir)
	oversized := make([]byte, layout.MaxKeyFileSize+1)
	if err := os.WriteFile(filepath.Join(staging, layout.FilePrivateKey), oversized, 0600); err != nil {
		t.Fatal(err)
	}

	got, err := FindStaging(dir)
	if err == nil {
		t.Fatal("FindStaging succeeded despite an oversized staged private key")
	}
	if got != "" {
		t.Errorf("FindStaging returned %q alongside an error", got)
	}
}
