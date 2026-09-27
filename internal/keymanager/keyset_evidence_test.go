package keymanager

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// metadata.json is written only after a key set is published, so a directory
// holding it and none of the key files lost a set. New must refuse rather
// than generate a fresh one, and must leave the marker as it found it.
func TestNewRefusesToRegenerateWhenMetadataRecordsAKeySet(t *testing.T) {
	dir := t.TempDir()
	first, err := New(dir, silentLog{})
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	for _, name := range []string{filePrivateKey, filePublicKey, fileRefreshSecret} {
		if err := os.Remove(filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	metaPath := filepath.Join(dir, fileMetadata)
	metaBefore, err := os.ReadFile(metaPath)
	if err != nil {
		t.Fatal(err)
	}

	_, err = New(dir, silentLog{})
	want := `held a key set (metadata.json records key id "` + first.KeyID() + `")`
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("New = %v, want the refusal naming the recorded key id", err)
	}
	if strings.Contains(err.Error(), "delete all key files") {
		t.Fatalf("the refusal advises deleting key files: %v", err)
	}
	for _, name := range []string{filePrivateKey, filePublicKey, fileRefreshSecret} {
		if _, statErr := os.Lstat(filepath.Join(dir, name)); !os.IsNotExist(statErr) {
			t.Fatalf("%s was created by the refused New (%v)", name, statErr)
		}
	}
	if metaAfter, _ := os.ReadFile(metaPath); !bytes.Equal(metaBefore, metaAfter) {
		t.Fatalf("metadata.json changed:\nbefore %s\nafter  %s", metaBefore, metaAfter)
	}

	// The documented way to start over: delete the marker, and New
	// generates a new set.
	if err := os.Remove(metaPath); err != nil {
		t.Fatal(err)
	}
	second, err := New(dir, silentLog{})
	if err != nil {
		t.Fatalf("New after deleting metadata.json: %v", err)
	}
	if second.KeyID() == first.KeyID() {
		t.Fatal("a fresh set carries the old key id")
	}
}
