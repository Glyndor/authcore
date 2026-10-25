package fsguard

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
)

// TestCreateExclusiveRefusesAnExistingFile covers the narrower race the old
// code lost: a regular file appearing between the presence check and the
// write kept its own permissions, so a world-readable file planted at that
// moment received the private key.
func TestCreateExclusiveRefusesAnExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, layout.FilePrivateKey)
	if err := os.WriteFile(path, nil, 0644); err != nil {
		t.Fatal(err)
	}
	if err := CreateExclusive(path, []byte("secret"), 0600); err == nil {
		t.Fatal("createExclusive overwrote an existing file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 0 {
		t.Errorf("the existing file was written to anyway: %q", data)
	}
}
