package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager"
)

// TestRotationRecipeKeepsTheRefreshSecret follows, step by step, the on-disk
// recipe in docs/guides/key-management.md ("Rotating the signing key"): a new
// complete set from authcore-keygen, the old refresh_secret.key written over
// the new one, and the secret_binding line removed from metadata.json. The
// directory must then load with a new signing key and the old secret, because
// every stored refresh-token hash and encrypted column depends on that secret.
// If the recipe in the guide changes, change this test with it.
func TestRotationRecipeKeepsTheRefreshSecret(t *testing.T) {
	root := t.TempDir()
	oldDir := filepath.Join(root, "keys-old")
	newDir := filepath.Join(root, "keys-new")

	if code, _, stderr := runKeygen(t, []string{"-out", oldDir}); code != 0 {
		t.Fatalf("old set: exit %d; stderr=%q", code, stderr)
	}
	oldSecret, err := os.ReadFile(filepath.Join(oldDir, "refresh_secret.key"))
	if err != nil {
		t.Fatalf("read old secret: %v", err)
	}
	oldKM, err := keymanager.Load(oldDir, keygenSilentLog{})
	if err != nil {
		t.Fatalf("load old set: %v", err)
	}

	// Step 1: a complete set in a new directory.
	if code, _, stderr := runKeygen(t, []string{"-out", newDir}); code != 0 {
		t.Fatalf("step 1: exit %d; stderr=%q", code, stderr)
	}
	// Step 2: the old secret over the generated one, mode 0600.
	secretPath := filepath.Join(newDir, "refresh_secret.key")
	if err := os.WriteFile(secretPath, oldSecret, 0o600); err != nil {
		t.Fatalf("step 2: %v", err)
	}
	// Step 3: drop the secret_binding line from metadata.json.
	dropSecretBinding(t, filepath.Join(newDir, "metadata.json"))

	newKM, err := keymanager.Load(newDir, keygenSilentLog{})
	if err != nil {
		t.Fatalf("the documented recipe did not produce a loadable directory: %v", err)
	}
	if !bytes.Equal(newKM.RefreshSecret(), oldKM.RefreshSecret()) {
		t.Error("the refresh secret changed across the rotation")
	}
	if newKM.KeyID() == oldKM.KeyID() {
		t.Error("the signing key did not change across the rotation")
	}
	got, err := os.ReadFile(secretPath)
	if err != nil || !bytes.Equal(got, oldSecret) {
		t.Errorf("refresh_secret.key was not preserved byte for byte (read err: %v)", err)
	}
}

// dropSecretBinding removes the secret_binding member from the metadata file
// at path, leaving every other member as it was.
func dropSecretBinding(t *testing.T, path string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	delete(members, "secret_binding")
	out, err := json.Marshal(members)
	if err != nil {
		t.Fatalf("encode %s: %v", path, err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
