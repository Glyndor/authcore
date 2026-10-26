package keyload_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/keyload"
	"github.com/Glyndor/authcore/internal/keymanager/keyload/keyloadtest"
	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/seams"
)

func withReadHook(t *testing.T, fn func(attempt, file int)) {
	t.Helper()
	prev := seams.AfterKeyRead
	seams.AfterKeyRead = fn
	t.Cleanup(func() { seams.AfterKeyRead = prev })
}

// The number of times a replaced set is read again is a documented bound:
// three reads, then the refusal.
func TestFiles_GivesUpAfterExactlyThreeReads(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows cannot rename over or remove a file this code holds open (no FILE_SHARE_DELETE), so the replacement this test performs mid-read cannot happen")
	}
	dir := t.TempDir()
	keyloadtest.WriteSet(t, dir)
	reads := 0
	withReadHook(t, func(attempt, file int) {
		if file != 2 {
			return
		}
		reads++
		staging := t.TempDir()
		keyloadtest.WriteSet(t, staging)
		for _, name := range layout.KeyFileNames() {
			if err := os.Rename(filepath.Join(staging, name), filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}
		}
	})

	if _, _, _, err := keyload.Files(dir, keyloadtest.SilentLog{}); err == nil {
		t.Fatal("Files accepted a set that changed on every read")
	}
	if reads != 3 {
		t.Fatalf("the set was read %d times, want 3", reads)
	}
}

// A file that is missing when it is opened may be a replacement in progress:
// the read is repeated, even though the files already read still lead to the
// descriptors held.
func TestFiles_RepeatsTheReadWhenAFileIsMissingAtOpen(t *testing.T) {
	dir := t.TempDir()
	set := keyloadtest.WriteSet(t, dir)
	pubPath := filepath.Join(dir, layout.FilePublicKey)
	aside := pubPath + ".aside"
	withReadHook(t, func(attempt, file int) {
		if file != 0 {
			return
		}
		switch attempt {
		case 0:
			if err := os.Rename(pubPath, aside); err != nil {
				t.Fatal(err)
			}
		case 1:
			if err := os.Rename(aside, pubPath); err != nil {
				t.Fatal(err)
			}
		}
	})

	priv, pub, secret, err := keyload.Files(dir, keyloadtest.SilentLog{})
	if err != nil {
		t.Fatalf("Files = %v, want the set once the file is back", err)
	}
	if !priv.Equal(set.Priv) || !pub.Equal(set.Pub) || string(secret) != string(set.Secret) {
		t.Fatal("Files returned a different set")
	}
}

// Every refusal names the file it is about, and only that one.
func TestFiles_RefusalsNameTheOffendingFile(t *testing.T) {
	cases := []struct {
		name, bad, other1, other2 string
	}{
		{"private key", layout.FilePrivateKey, layout.FilePublicKey, layout.FileRefreshSecret},
		{"public key", layout.FilePublicKey, layout.FilePrivateKey, layout.FileRefreshSecret},
		{"refresh secret", layout.FileRefreshSecret, layout.FilePrivateKey, layout.FilePublicKey},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			keyloadtest.WriteSet(t, dir)
			keyloadtest.Put(t, dir, c.bad, []byte("garbage"), 0o600)

			_, _, _, err := keyload.Files(dir, keyloadtest.SilentLog{})
			if err == nil {
				t.Fatal("Files accepted a corrupt file")
			}
			msg := err.Error()
			if !strings.Contains(msg, c.bad) || strings.Contains(msg, c.other1) || strings.Contains(msg, c.other2) {
				t.Fatalf("the refusal does not single out %s: %v", c.bad, err)
			}
		})
	}
}

func TestFiles_PairMismatchNamesPublicThenPrivate(t *testing.T) {
	dir := t.TempDir()
	keyloadtest.WriteSet(t, dir)
	foreign := t.TempDir()
	keyloadtest.WriteSet(t, foreign)
	data, err := os.ReadFile(filepath.Join(foreign, layout.FilePublicKey))
	if err != nil {
		t.Fatal(err)
	}
	keyloadtest.Put(t, dir, layout.FilePublicKey, data, 0o644)

	_, _, _, err = keyload.Files(dir, keyloadtest.SilentLog{})
	if err == nil {
		t.Fatal("Files accepted a public key that belongs to another private key")
	}
	want := "public key in " + strconv.Quote(filepath.Join(dir, layout.FilePublicKey)) +
		" does not match private key in " + strconv.Quote(filepath.Join(dir, layout.FilePrivateKey))
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("err = %v\nwant it to contain %s", err, want)
	}
}

func TestCheck_RefusesAnOversizedPrivateKey(t *testing.T) {
	dir := t.TempDir()
	keyloadtest.WriteSet(t, dir)
	keyloadtest.Put(t, dir, layout.FilePrivateKey, make([]byte, layout.MaxKeyFileSize+1), 0o600)
	if err := keyload.Check(dir); err == nil || !strings.Contains(err.Error(), "load private key") || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("Check = %v, want the size refusal of the private key", err)
	}
}

func TestCheck_RefusesAMissingOrOversizedPublicKey(t *testing.T) {
	dir := t.TempDir()
	keyloadtest.WriteSet(t, dir)
	if err := keyload.Check(dir); err != nil {
		t.Fatalf("Check on a good set = %v", err)
	}

	keyloadtest.Put(t, dir, layout.FilePublicKey, make([]byte, layout.MaxKeyFileSize+1), 0o644)
	if err := keyload.Check(dir); err == nil || !strings.Contains(err.Error(), "load public key") || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("Check on an oversized public key = %v, want a load public key error", err)
	}

	if err := os.Remove(filepath.Join(dir, layout.FilePublicKey)); err != nil {
		t.Fatal(err)
	}
	if err := keyload.Check(dir); err == nil || !strings.Contains(err.Error(), "load public key") {
		t.Fatalf("Check on a missing public key = %v, want a load public key error", err)
	}
}

// The two secret files are checked for modes others can read or write, and the
// public key is not: it is meant to be shared.
func TestFiles_WarnsAboutEachSecretFileOthersCanRead(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no Unix permission bits: Chmod only toggles read-only and Stat reports a synthetic mode")
	}
	cases := []struct {
		name, file string
		warns      int
	}{
		{"private key", layout.FilePrivateKey, 1},
		{"refresh secret", layout.FileRefreshSecret, 1},
		{"public key", layout.FilePublicKey, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			keyloadtest.WriteSet(t, dir)
			if err := os.Chmod(filepath.Join(dir, c.file), 0o644); err != nil {
				t.Fatal(err)
			}
			var rec keyloadtest.Recorder

			if _, _, _, err := keyload.Files(dir, &rec); err != nil {
				t.Fatal(err)
			}
			if len(rec.Warnings) != c.warns {
				t.Fatalf("warnings = %q, want %d", rec.Warnings, c.warns)
			}
			if c.warns == 1 && !strings.Contains(rec.Warnings[0], c.file) {
				t.Errorf("the warning does not name %s: %q", c.file, rec.Warnings[0])
			}
		})
	}
}
