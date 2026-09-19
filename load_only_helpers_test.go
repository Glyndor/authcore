package authcore_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"

	"github.com/Glyndor/authcore"
)

// dirEntry is one row of the directory listing snapshot. The fields are
// name, size, mode and modtime, the four attributes the load-only tests
// assert on.
//
// The listing is captured by walking dir once with os.ReadDir and Stat. It
// uses the same view the loaders see (Stat follows symlinks), so a missing
// file in a snapshot is the same missing file the loader saw.
type dirEntry struct {
	name  string
	size  int64
	mode  os.FileMode
	mtime int64
}

// snapshotDir captures every regular-file entry of dir with enough fidelity
// to tell a write from a no-op afterwards. Non-regular entries are skipped:
// load-only New never creates those, so they would only show up as a
// bug-induced file and the comparison is cleaner without them.
func snapshotDir(t *testing.T, dir string) []dirEntry {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir %s: %v", dir, err)
	}
	out := make([]dirEntry, 0, len(entries))
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			t.Fatalf("Info %s: %v", e.Name(), err)
		}
		if !info.Mode().IsRegular() {
			continue
		}
		out = append(out, dirEntry{
			name:  e.Name(),
			size:  info.Size(),
			mode:  info.Mode(),
			mtime: info.ModTime().UnixNano(),
		})
	}
	return out
}

// assertDirUnchanged compares a directory listing taken before the test body
// to one taken after and fails the test on any difference: name, size, mode
// or mod time. The size and mtime checks are the load-only contract's
// whole point.
func assertDirUnchanged(t *testing.T, dir string, before []dirEntry) {
	t.Helper()
	after := snapshotDir(t, dir)
	if len(before) != len(after) {
		names := func(e []dirEntry) []string {
			out := make([]string, len(e))
			for i, x := range e {
				out[i] = x.name
			}
			return out
		}
		t.Fatalf("directory listing changed: before=%v after=%v", names(before), names(after))
	}
	for i, b := range before {
		a := after[i]
		if a.name != b.name || a.size != b.size || a.mode != b.mode || a.mtime != b.mtime {
			t.Fatalf("entry %d changed: before=%+v after=%+v", i, b, a)
		}
	}
}

// seedDir runs the standard authcore.New against dir to leave a known-good
// three-file set there, and returns the keys it produced. Returning the
// pre-key id lets the load-only tests assert on key id equality.
func seedDir(t *testing.T, dir string) authcore.Keys {
	t.Helper()
	cfg := authcore.DefaultConfig()
	cfg.EnableLogs = false
	cfg.KeysDir = dir
	ac, err := authcore.New(cfg)
	if err != nil {
		t.Fatalf("seed New: %v", err)
	}
	return ac.Keys()
}

// mustMarshalPKCS8 / mustMarshalPKIX turn Ed25519 keys into the PEM bytes
// the loader expects. They live in a test helper because the encoding is a
// stable detail of the disk layout, and any drift would show up as an
// integration failure before a unit test could catch it.
func mustMarshalPKCS8(t *testing.T, k ed25519.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatalf("marshal PKCS8: %v", err)
	}
	return der
}

func mustMarshalPKIX(t *testing.T, k ed25519.PublicKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		t.Fatalf("marshal PKIX: %v", err)
	}
	return der
}

// randSecretBytes returns 32 random bytes for the refresh secret. It is a
// helper rather than a fixture because the bytes themselves are arbitrary
// and never asserted on.
func randSecretBytes(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand secret: %v", err)
	}
	return b
}

var _ = filepath.Join // keep the import live for any future fixture
