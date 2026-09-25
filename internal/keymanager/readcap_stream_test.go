package keymanager

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// readCapped refuses an oversized key file twice: once on the size Stat
// reports, and again when the read itself delivers more than the cap. The
// second check is for a file that grows between the Stat and the read. Until
// these tests nothing reached it, so it could be deleted with the suite green.
// /dev/zero stands in for such a file: Stat reports zero bytes and the read
// never ends. Through Load and New a device never gets that far, because the
// regular-file check refuses it first; the end-to-end test below pins that.

const streamRefusal = "exceeds 4096-byte cap"

func endlessStream(t *testing.T) string {
	t.Helper()
	const path = "/dev/zero"
	if _, err := os.Stat(path); err != nil {
		t.Skipf("%s is not available on %s: the read-time cap is not exercised here", path, runtime.GOOS)
	}
	return path
}

func TestReadCapped_refusesAStreamLongerThanTheCap(t *testing.T) {
	_, err := readCapped(endlessStream(t))
	if err == nil || !strings.Contains(err.Error(), streamRefusal) {
		t.Fatalf("readCapped(/dev/zero) = %v, want the read-time refusal %q", err, streamRefusal)
	}
	// The Stat check words its refusal with the size it saw; this one must
	// not have been it, or the read-time check is still untested.
	if strings.Contains(err.Error(), "bytes, exceeds") {
		t.Fatalf("refused by the Stat check, not the read-time check: %v", err)
	}
}

// The pair on each side of the cap, from regular files: exactly the cap is
// read whole, one byte more is refused by the Stat check.
func TestReadCapped_regularFilesAtAndPastTheCap(t *testing.T) {
	dir := t.TempDir()

	atCap := filepath.Join(dir, "at-cap")
	if err := os.WriteFile(atCap, bytes.Repeat([]byte{'a'}, maxKeyFileSize), 0600); err != nil {
		t.Fatal(err)
	}
	data, err := readCapped(atCap)
	if err != nil || len(data) != maxKeyFileSize {
		t.Fatalf("readCapped at the cap: %d bytes, %v; want %d, nil", len(data), err, maxKeyFileSize)
	}

	pastCap := filepath.Join(dir, "past-cap")
	if err := os.WriteFile(pastCap, bytes.Repeat([]byte{'a'}, maxKeyFileSize+1), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readCapped(pastCap); err == nil || !strings.Contains(err.Error(), "is 4097 bytes, exceeds 4096-byte cap") {
		t.Fatalf("readCapped one past the cap = %v, want the Stat refusal", err)
	}
}

// End to end: a provisioned key set whose refresh secret has been replaced by
// a link to an endless stream. Load must refuse it, and New must refuse it
// too rather than read the slot as absent and generate a fresh set beside the
// existing private key. Measured when this was written: the refusal comes from
// the regular-file check, before any read.
func TestKeyFileLinkedToAnEndlessStreamIsRefused(t *testing.T) {
	stream := endlessStream(t)
	dir := t.TempDir()
	if _, err := New(dir, silentLog{}); err != nil {
		t.Fatalf("provision: %v", err)
	}
	privBefore, err := os.ReadFile(filepath.Join(dir, filePrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(dir, fileRefreshSecret)
	if err := os.Remove(secret); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(stream, secret); err != nil {
		t.Fatal(err)
	}

	const notRegular = "not a regular file"
	if _, err := Load(dir, silentLog{}); err == nil || !strings.Contains(err.Error(), notRegular) {
		t.Fatalf("Load = %v, want the refusal %q", err, notRegular)
	}
	if _, err := New(dir, silentLog{}); err == nil || !strings.Contains(err.Error(), notRegular) {
		t.Fatalf("New = %v, want the refusal %q", err, notRegular)
	}
	privAfter, err := os.ReadFile(filepath.Join(dir, filePrivateKey))
	if err != nil || !bytes.Equal(privBefore, privAfter) {
		t.Fatalf("the private key changed or went missing (%v)", err)
	}
}

// A KeysDir below a regular file cannot be inspected at all. New and Load
// report that, naming the directory, instead of treating it as absent.
func TestKeysDirBelowARegularFileIsReported(t *testing.T) {
	base := t.TempDir()
	file := filepath.Join(base, "not-a-directory")
	if err := os.WriteFile(file, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(file, "keys")

	for name, open := range map[string]func(string, logger) (*KeyManager, error){"New": New, "Load": Load} {
		_, err := open(dir, silentLog{})
		if err == nil || !strings.Contains(err.Error(), `inspect key directory "`+dir+`"`) {
			t.Errorf("%s(%q) = %v, want the inspect error naming the directory", name, dir, err)
		}
	}
	if entries, err := os.ReadDir(base); err != nil || len(entries) != 1 {
		t.Fatalf("something was created beside the file: %v, %v", entries, err)
	}
}
