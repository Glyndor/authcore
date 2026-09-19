// Helper section for the load-only test file: builders that drop a known-good
// trio into a directory, the PEM-bytes marshallers, a tiny hex encoder, and
// the directory listing snapshot primitives that the load-only tests use to
// prove Load is a true no-op on disk.
//
// Split into its own file so load_test.go stays focused on the cases
// themselves, and so the helper logic does not crowd them.

package keymanager_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

// writeValidKeys drops a known-good trio into dir. Used by the metadata
// corruption test, which only needs the three files present to drive its
// scenario; the values themselves are not asserted on.
func writeValidKeys(t *testing.T, dir string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: mustMarshalPKCS8(t, priv),
	})
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: mustMarshalPKIX(t, pub),
	})
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	if err := os.WriteFile(filepath.Join(dir, "ed25519_private.pem"), privPEM, 0600); err != nil {
		t.Fatalf("write priv: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ed25519_public.pem"), pubPEM, 0644); err != nil {
		t.Fatalf("write pub: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "refresh_secret.key"), append(hexEncode(secret), '\n'), 0600); err != nil {
		t.Fatalf("write secret: %v", err)
	}
}

// mustMarshalPKCS8 / mustMarshalPKIX turn Ed25519 keys into the PEM bytes
// the loader expects. They live in helpers so a load-only test that needs
// a custom key pair can build one without duplicating the PEM dance.
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

// hexEncode produces the lowercase hex encoding the on-disk refresh secret
// uses, so a fixture written via writeValidKeys matches what the loader
// reads on the next pass.
func hexEncode(b []byte) []byte {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[2*i] = hexdigits[c>>4]
		out[2*i+1] = hexdigits[c&0xF]
	}
	return out
}

// ----- directory listing snapshot primitives ---------------------------------
//
// The load-only tests use these to prove that Load never wrote anything:
// a listing captured before the call is compared with one captured after.
// The modtime is captured to nanosecond precision so a metadata.json write
// or a chmod would shift it.

// dirEntry is one row of a directory listing snapshot.
type dirEntry struct {
	name  string
	size  int64
	mode  os.FileMode
	mtime int64 // unix nanos; ModTime().UnixNano() is stable across reads
}

// snapshotListing captures every entry of dir (Stat, following symlinks, the
// same view the loaders see) so a later comparison can prove Load was a true
// no-op.
func snapshotListing(t *testing.T, dir string) []dirEntry {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatalf("ReadDir %s: %v", dir, err)
	}
	out := make([]dirEntry, 0, len(entries))
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			t.Fatalf("Info %s: %v", e.Name(), err)
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

// snapshotBytes holds every file in dir by name, byte for byte. It exists so
// the metadata.json absence test can pin "every byte of every file is
// unchanged" without going through the listing helper.
func snapshotBytes(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir %s: %v", dir, err)
	}
	out := make(map[string][]byte, len(entries))
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			t.Fatalf("Info %s: %v", e.Name(), err)
		}
		if !info.Mode().IsRegular() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name())) // #nosec G304 -- test fixture path
		if err != nil {
			t.Fatalf("ReadFile %s: %v", e.Name(), err)
		}
		out[e.Name()] = data
	}
	return out
}

func assertListingUnchanged(t *testing.T, dir string, before []dirEntry) {
	t.Helper()
	after := snapshotListing(t, dir)
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

func assertBytesUnchanged(t *testing.T, dir string, before map[string][]byte) {
	t.Helper()
	after := snapshotBytes(t, dir)
	if len(before) != len(after) {
		t.Fatalf("file count changed: before=%d after=%d", len(before), len(after))
	}
	for name, want := range before {
		got, ok := after[name]
		if !ok {
			t.Fatalf("file %q disappeared", name)
		}
		if string(got) != string(want) {
			t.Fatalf("file %q was rewritten", name)
		}
	}
}
