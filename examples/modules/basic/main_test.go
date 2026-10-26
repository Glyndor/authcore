package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Glyndor/authcore"
)

// TestRunPrintsTheDocumentedConfiguration runs the example.
func TestRunPrintsTheDocumentedConfiguration(t *testing.T) {
	var out bytes.Buffer
	if err := run(&out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"timezone      : UTC", "logs enabled  : true", "logs enabled  : false", "America/Bogota", "public key    : "} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q", want)
		}
	}
}

// spellings returns every textual form in which a secret could leak into a
// log line: hex, the base64 alphabets, the raw bytes, and Go's own formatting
// of a byte slice.
func spellings(secret []byte) []string {
	return []string{
		hex.EncodeToString(secret),
		base64.StdEncoding.EncodeToString(secret),
		base64.RawStdEncoding.EncodeToString(secret),
		base64.URLEncoding.EncodeToString(secret),
		base64.RawURLEncoding.EncodeToString(secret),
		string(secret),
		fmt.Sprintf("%v", secret),
	}
}

// TestLoggerNeverSeesKeyMaterial plugs the example's logger in, creates keys
// and loads them again, and requires that no secret reaches what the logger
// wrote. This is the path a copied logger ships to a log aggregator.
func TestLoggerNeverSeesKeyMaterial(t *testing.T) {
	dir := t.TempDir()
	var logged bytes.Buffer

	cfg := authcore.DefaultConfig()
	cfg.Logger = &myAppLogger{w: &logged}
	cfg.KeysDir = dir

	first, err := authcore.New(cfg) // creates the keys
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authcore.New(cfg); err != nil { // loads them
		t.Fatal(err)
	}
	if logged.Len() == 0 {
		t.Fatal("the logger saw nothing: the test would pass on any leak")
	}

	for name, secret := range map[string][]byte{
		"private key": first.Keys().PrivateKey(), "private seed": first.Keys().PrivateKey()[:32],
		"refresh secret": first.Keys().RefreshSecret(),
	} {
		for _, form := range spellings(secret) {
			if form != "" && strings.Contains(logged.String(), form) {
				t.Errorf("the %s appears in the log as %.12q", name, form)
			}
		}
	}
}

// TestKeysSurviveARestart checks the claim behind "let authcore manage the
// directory": a second start loads the same keys instead of minting new ones,
// which would silently invalidate every token and stored hash.
func TestKeysSurviveARestart(t *testing.T) {
	cfg := authcore.Config{KeysDir: t.TempDir()}
	first, err := authcore.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	second, err := authcore.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if first.Keys().KeyID() != second.Keys().KeyID() ||
		!bytes.Equal(first.Keys().PublicKey(), second.Keys().PublicKey()) ||
		!bytes.Equal(first.Keys().RefreshSecret(), second.Keys().RefreshSecret()) {
		t.Error("a restart changed the key material")
	}

	other, err := authcore.New(authcore.Config{KeysDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if other.Keys().KeyID() == first.Keys().KeyID() || bytes.Equal(other.Keys().RefreshSecret(), first.Keys().RefreshSecret()) {
		t.Error("two key directories share key material")
	}
}

// TestKeyFilesAreNotWorldReadable checks what the example leaves on disk. The
// default directory is the project root, so this is also what ends up next to
// the source tree.
func TestKeyFilesAreNotWorldReadable(t *testing.T) {
	t.Chdir(t.TempDir())
	cfg := authcore.DefaultConfig() // KeysDir left unset: the default directory
	cfg.EnableLogs = false
	if _, err := authcore.New(cfg); err != nil {
		t.Fatal(err)
	}

	dir := ".authcore"
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("the default keys directory is not %s: %v", dir, err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Errorf("%s is %v: group or others can enter it", dir, info.Mode().Perm())
	}

	var files int
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		files++
		fi, _ := d.Info()
		if strings.Contains(d.Name(), "public") {
			return nil // the public half is meant to be shared
		}
		if fi.Mode().Perm()&0o007 != 0 {
			t.Errorf("%s is %v: readable by others", path, fi.Mode().Perm())
		}
		return nil
	})
	if files == 0 {
		t.Error("no key files were written")
	}
	if ignore, err := os.ReadFile(filepath.Join(dir, ".gitignore")); err != nil || !strings.Contains(string(ignore), "*") {
		t.Errorf("the directory does not ignore itself, so a git add . would commit the keys: %v", err)
	}
}
