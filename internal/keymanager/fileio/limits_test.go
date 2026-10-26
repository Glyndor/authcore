package fileio_test

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/fileio"
	"github.com/Glyndor/authcore/internal/keymanager/layout"
)

func writeSized(t *testing.T, size int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, []byte(strings.Repeat("a", size)), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// The cap is part of the contract: a file of exactly MaxKeyFileSize bytes is
// read whole and one byte more is refused.
func TestReadCapped_BoundaryIsExactlyFourKiB(t *testing.T) {
	if layout.MaxKeyFileSize != 4096 {
		t.Fatalf("MaxKeyFileSize = %d, want 4096", layout.MaxKeyFileSize)
	}

	got, err := fileio.ReadCapped(writeSized(t, 4096))
	if err != nil || len(got) != 4096 {
		t.Fatalf("ReadCapped(4096 bytes) = %d bytes, %v; want the whole file", len(got), err)
	}

	if _, err := fileio.ReadCapped(writeSized(t, 4097)); err == nil {
		t.Fatal("ReadCapped accepted a file one byte over the cap")
	}
}

// A source that streams more than Stat reported is cut one byte past the cap,
// not further: the loader must not pull an attacker-sized stream into memory.
func TestReadCappedFile_StopsOneByteAfterTheCap(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })

	const extra = 10
	if _, err := w.Write([]byte(strings.Repeat("b", layout.MaxKeyFileSize+extra))); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()

	if _, err := fileio.ReadCappedFile(r, "stream"); err == nil {
		t.Fatal("ReadCappedFile accepted a stream longer than the cap")
	}

	rest, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if want := extra - 1; len(rest) != want {
		t.Fatalf("%d bytes were left unread, want %d: the read went past cap+1", len(rest), want)
	}
}

func TestReadCappedFile_ReportsAReadFailure(t *testing.T) {
	f, err := os.Open(writeSized(t, 8))
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	data, err := fileio.ReadCappedFile(f, "closed")
	if err == nil {
		t.Fatalf("ReadCappedFile on a closed descriptor returned %q and no error", data)
	}
}
