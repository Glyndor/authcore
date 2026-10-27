package authcore_test

import (
	"os"
	"testing"

	"github.com/Glyndor/authcore"
)

// TestNew_keysDirWithExistingKeysIsNotWriteProbed verifies that, once the key
// files exist, New does not require the directory to be writable — the
// recommended container deployment mounts pre-generated keys read-only. New
// must load them instead of refusing to start over a write check.
func TestNew_keysDirWithExistingKeysIsNotWriteProbed(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permission bits")
	}

	dir := t.TempDir()

	cfg := authcore.DefaultConfig()
	cfg.EnableLogs = false
	cfg.KeysDir = dir

	// First run generates the key files.
	if _, err := authcore.New(cfg); err != nil {
		t.Fatalf("initial New: %v", err)
	}

	// Restrict the directory to read+execute (no write), as a read-only secret
	// mount would, and reload. With the keys already present this must succeed.
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0700) })

	ac, err := authcore.New(cfg)
	if err != nil {
		t.Fatalf("New with existing keys in a restricted dir must succeed, got %v", err)
	}
	if ac.Keys() == nil || len(ac.Keys().PrivateKey()) == 0 {
		t.Error("keys were not loaded from the existing directory")
	}
}
