package authcore_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Glyndor/authcore"
)

// TestNew_unwritableKeysDirReturnsError covers the write-check error path in
// validateKeysDir: a directory that exists but cannot be written to must be
// rejected before the key manager runs. Skipped when running as root, which
// bypasses filesystem permission bits.
func TestNew_unwritableKeysDirReturnsError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permission bits")
	}

	dir := filepath.Join(t.TempDir(), "readonly")
	if err := os.Mkdir(dir, 0500); err != nil { // r-x: present but not writable
		t.Fatalf("create read-only dir: %v", err)
	}

	cfg := authcore.DefaultConfig()
	cfg.EnableLogs = false
	cfg.KeysDir = dir

	_, err := authcore.New(cfg)
	if err == nil {
		t.Fatal("expected error for unwritable keys directory, got nil")
	}
	if !errors.Is(err, authcore.ErrInvalidConfig) {
		t.Errorf("error = %v, want ErrInvalidConfig", err)
	}
}
