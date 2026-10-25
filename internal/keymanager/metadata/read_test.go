package metadata

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/seams"
)

func withFault(t *testing.T, fn func(string) error) {
	t.Helper()
	prev := seams.FaultAt
	seams.FaultAt = fn
	t.Cleanup(func() { seams.FaultAt = prev })
}

// seedDir returns a directory holding a private key (so the descriptor has
// something to date itself from) and the descriptor Sync wrote for it.
func seedDir(t *testing.T) (string, *Metadata) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, layout.FilePrivateKey), []byte("k"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Sync(dir, nil, "0123456789abcdef", "", &captureLogger{}); err != nil {
		t.Fatalf("seed Sync: %v", err)
	}
	m, err := Read(dir)
	if err != nil || m == nil {
		t.Fatalf("seed Read: %v, %v", m, err)
	}
	return dir, m
}

func metaEqual(a, b *Metadata) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Format == b.Format && a.Created == b.Created && a.KeyID == b.KeyID
}

// Atomic-replace test for metadata.json: a fault injected before the rename
// must leave the previous descriptor on disk and the temp file behind. A
// subsequent write must succeed and produce the new descriptor.
func TestMetadataReplaceIsAtomic(t *testing.T) {
	dir, oldM := seedDir(t)

	sentinel := errors.New("metadata fault before rename")
	withFault(t, func(p string) error {
		if p == "metadata-before-rename" {
			return sentinel
		}
		return nil
	})

	newM := *oldM
	newM.KeyID = "deadbeefdeadbeef"
	if err := write(dir, newM); !errors.Is(err, sentinel) {
		t.Fatalf("write under fault: want sentinel, got %v", err)
	}

	stillOld, err := Read(dir)
	if err != nil {
		t.Fatalf("Read after fault: %v", err)
	}
	if !metaEqual(stillOld, oldM) {
		t.Errorf("metadata changed across fault: got %+v, want %+v", stillOld, oldM)
	}

	withFault(t, func(string) error { return nil })
	if err := write(dir, newM); err != nil {
		t.Fatalf("write after fault cleared: %v", err)
	}

	now, err := Read(dir)
	if err != nil {
		t.Fatalf("Read after recovery: %v", err)
	}
	if now.KeyID != newM.KeyID {
		t.Errorf("metadata did not update: got key_id %q, want %q", now.KeyID, newM.KeyID)
	}
}

// Read rejects a descriptor whose format is below the supported
// minimum. The condition is reachable in production when a copy of an older
// or otherwise malformed metadata.json is restored from backup; a directory
// that passes everything else is still unsafe to load under that marker.
func TestRead_rejectsFormatBelowOne(t *testing.T) {
	dir, _ := seedDir(t)

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

	got, err := Read(dir)
	if err == nil {
		t.Fatal("Read accepted a descriptor with format 0")
	}
	if !strings.Contains(err.Error(), "invalid format") {
		t.Errorf("error must mention the invalid format, got: %v", err)
	}
	if got != nil {
		t.Errorf("Read returned a non-nil descriptor on rejection: %+v", got)
	}
}

func TestRead_missingDescriptorIsThePreMetadataLayout(t *testing.T) {
	m, err := Read(t.TempDir())
	if m != nil || err != nil {
		t.Fatalf("Read on a directory without a descriptor = %+v, %v; want nil, nil", m, err)
	}
}

func TestRead_refusesAFormatFromTheFuture(t *testing.T) {
	dir := t.TempDir()
	future := `{"format": 99, "created": "2030-01-01T00:00:00Z", "key_id": "0123456789abcdef"}`
	if err := os.WriteFile(filepath.Join(dir, layout.FileMetadata), []byte(future), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := Read(dir)
	if !errors.Is(err, ErrFormatFromFuture) {
		t.Fatalf("Read = %v, want ErrFormatFromFuture", err)
	}
	if !strings.Contains(err.Error(), "reports format 99") {
		t.Errorf("the error should name the format it saw: %v", err)
	}
}

func TestRead_corruptDescriptorNamesTheEscape(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, layout.FileMetadata), []byte("{not json"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := Read(dir)
	if err == nil || !strings.Contains(err.Error(), "deleting it is safe") {
		t.Fatalf("Read = %v, want the parse error naming the escape", err)
	}
}

// A descriptor that cannot be read at all is not the same as one that is
// absent: absent means the pre-marker layout and is adopted, while unreadable
// means the loader cannot tell what wrote the directory and must fail closed.
func TestRead_unreadableDescriptorFailsClosed(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, layout.FileMetadata), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(dir); err == nil {
		t.Fatal("a directory at the descriptor path must fail closed, not be treated as absent")
	}
}

func TestSync_writesADescriptorForAnAdoptedDirectory(t *testing.T) {
	dir := t.TempDir()
	log := &captureLogger{}
	if err := Sync(dir, nil, "0123456789abcdef", "", log); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	m, err := Read(dir)
	if err != nil || m == nil || m.KeyID != "0123456789abcdef" || m.Format != CurrentFormat {
		t.Fatalf("Read after Sync = %+v, %v", m, err)
	}
	if _, err := os.Stat(filepath.Join(dir, layout.FileMetadata)); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		fi, _ := os.Stat(filepath.Join(dir, layout.FileMetadata))
		if fi.Mode().Perm() != 0600 {
			t.Errorf("descriptor mode = %v, want 0600", fi.Mode().Perm())
		}
	}
}

func TestSync_followsARotatedKey(t *testing.T) {
	dir, old := seedDir(t)
	if err := Sync(dir, old, "ffffffffffffffff", "", &captureLogger{}); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	m, err := Read(dir)
	if err != nil || m.KeyID != "ffffffffffffffff" {
		t.Fatalf("Read after rotation = %+v, %v", m, err)
	}
	if m.Created != old.Created {
		t.Errorf("rotation rewrote the creation time: %q -> %q", old.Created, m.Created)
	}
}

// A faultAt return is a test-only signal: it is returned verbatim so the
// publish transaction aborts as a crash would, instead of being downgraded to
// the warning a real write failure gets.
func TestSync_faultAtIsReturnedNotDowngraded(t *testing.T) {
	dir, old := seedDir(t)
	sentinel := errors.New("fault on metadata-written")
	withFault(t, func(p string) error {
		if p == "metadata-written" {
			return sentinel
		}
		return nil
	})

	if err := Sync(t.TempDir(), nil, "0123456789abcdef", "", &captureLogger{}); !errors.Is(err, sentinel) {
		t.Errorf("adopting a directory: got %v, want the sentinel", err)
	}

	if err := Sync(dir, old, "ffffffffffffffff", "", &captureLogger{}); !errors.Is(err, sentinel) {
		t.Errorf("rotating a key: got %v, want the sentinel", err)
	}
}

func TestCreationTime_fallsBackToNowWithoutAPrivateKey(t *testing.T) {
	got := creationTime(t.TempDir())
	if _, err := time.Parse(time.RFC3339, got); err != nil {
		t.Fatalf("creationTime = %q, not RFC 3339: %v", got, err)
	}
}
