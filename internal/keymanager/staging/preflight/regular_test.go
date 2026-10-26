package preflight_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/staging/preflight"
)

// Only a link is refused; a regular file at a key name is not this check's
// business (the key-set inspection classifies it).
func TestSymlinks_AcceptsRegularFiles(t *testing.T) {
	dir := t.TempDir()
	for _, name := range layout.KeyFileNames() {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := preflight.Symlinks(dir); err != nil {
		t.Fatalf("Symlinks = %v, want nil for regular files", err)
	}
}
