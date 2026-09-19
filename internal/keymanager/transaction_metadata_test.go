package keymanager

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Atomic-replace test for metadata.json: a fault injected before the rename
// must leave the previous descriptor on disk and the temp file behind. A
// subsequent write must succeed and produce the new descriptor.

func TestMetadataReplaceIsAtomic(t *testing.T) {
	dir := t.TempDir()
	if _, err := New(dir, silentLog{}); err != nil {
		t.Fatalf("seed New: %v", err)
	}
	oldM, err := readMetadata(dir)
	if err != nil {
		t.Fatalf("readMetadata: %v", err)
	}

	sentinel := errors.New("metadata fault before rename")
	withFaultAt(t, func(p string) error {
		if p == "metadata-before-rename" {
			return sentinel
		}
		return nil
	})

	newM := *oldM
	newM.KeyID = "deadbeefdeadbeef"
	if err := writeMetadata(dir, newM); !errors.Is(err, sentinel) {
		t.Fatalf("writeMetadata under fault: want sentinel, got %v", err)
	}

	stillOld, err := readMetadata(dir)
	if err != nil {
		t.Fatalf("readMetadata after fault: %v", err)
	}
	if !metaEqual(stillOld, oldM) {
		t.Errorf("metadata changed across fault: got %+v, want %+v", stillOld, oldM)
	}

	withFaultAt(t, nil)
	if err := writeMetadata(dir, newM); err != nil {
		t.Fatalf("writeMetadata after fault cleared: %v", err)
	}

	now, err := readMetadata(dir)
	if err != nil {
		t.Fatalf("readMetadata after recovery: %v", err)
	}
	if now.KeyID != newM.KeyID {
		t.Errorf("metadata did not update: got key_id %q, want %q", now.KeyID, newM.KeyID)
	}
}

// readMetadata rejects a descriptor whose format is below the supported
// minimum. The condition is reachable in production when a copy of an older
// or otherwise malformed metadata.json is restored from backup; a directory
// that passes everything else is still unsafe to load under that marker.
func TestReadMetadata_rejectsFormatBelowOne(t *testing.T) {
	dir := t.TempDir()
	if _, err := New(dir, silentLog{}); err != nil {
		t.Fatalf("seed New: %v", err)
	}

	broken, err := json.Marshal(struct {
		Format  int    `json:"format"`
		Created string `json:"created"`
		KeyID   string `json:"key_id"`
	}{Format: 0, Created: "2026-01-01T00:00:00Z", KeyID: "deadbeefdeadbeef"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "metadata.json"), broken, 0600); err != nil {
		t.Fatal(err)
	}

	got, err := readMetadata(dir)
	if err == nil {
		t.Fatal("readMetadata accepted a descriptor with format 0")
	}
	if !strings.Contains(err.Error(), "invalid format") {
		t.Errorf("error must mention the invalid format, got: %v", err)
	}
	if got != nil {
		t.Errorf("readMetadata returned a non-nil descriptor on rejection: %+v", got)
	}
}
