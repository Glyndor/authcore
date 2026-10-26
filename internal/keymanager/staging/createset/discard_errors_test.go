package createset_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/staging/createset"
)

// Every entry that could not be removed is named in the error: what is left
// may hold key material that was never published.
func TestDiscard_NamesEachEntryItCouldNotRemove(t *testing.T) {
	staging := filepath.Join(t.TempDir(), ".staging-x")
	held := filepath.Join(staging, layout.FilePrivateKey)
	if err := os.MkdirAll(held, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(held, "f"), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	err := createset.Discard(staging)
	if err == nil || !strings.Contains(err.Error(), "never published") {
		t.Fatalf("Discard = %v, want the removal error", err)
	}
	if !strings.Contains(err.Error(), held) {
		t.Errorf("err = %v, want it to name %s", err, held)
	}
}

func TestCreate_RefusesADirectoryItCannotSync(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o300); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	if _, _, _, _, err := createset.Create(dir); err == nil || !strings.Contains(err.Error(), "sync keys directory") {
		t.Fatalf("Create = %v, want the failed directory sync", err)
	}
}
