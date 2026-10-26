package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/apikey"
)

func newModule(t *testing.T) *apikey.APIKey {
	t.Helper()
	auth, err := authcore.New(authcore.Config{KeysDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	mod, err := apikey.New(auth)
	if err != nil {
		t.Fatal(err)
	}
	return mod
}

// TestRunShowsTheDocumentedFlow runs the example. It prints the key because
// the example is the moment a key is shown once; the stored hash must not
// contain that key.
func TestRunShowsTheDocumentedFlow(t *testing.T) {
	t.Chdir(t.TempDir())
	var out bytes.Buffer
	if err := run(&out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Verify correct key  : true", "Verify tampered key : false", "Malformed key rejected:"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q", want)
		}
	}
}

// TestStoredHashDoesNotRevealTheKey checks what the example tells you to store.
func TestStoredHashDoesNotRevealTheKey(t *testing.T) {
	mod := newModule(t)
	key, err := mod.Generate()
	if err != nil {
		t.Fatal(err)
	}
	secret := strings.TrimPrefix(key.Key, key.ID)
	if key.Hash == key.Key || strings.Contains(key.Hash, secret) || len(secret) < 16 {
		t.Errorf("the stored hash is the key, or contains its secret part (secret length %d)", len(secret))
	}

	other, _ := mod.Generate()
	if other.Key == key.Key || other.ID == key.ID || other.Hash == key.Hash {
		t.Error("two generated keys share an id, a key or a hash")
	}
}

// TestVerifyFailsClosed feeds the verification the inputs a handler meets: a
// missing stored hash (the id was not found), a missing key, another account's
// key, and edits of the right key.
func TestVerifyFailsClosed(t *testing.T) {
	mod := newModule(t)
	key, _ := mod.Generate()
	other, _ := mod.Generate()

	if !mod.Verify(key.Key, key.Hash) {
		t.Fatal("the issued key does not verify against its own hash")
	}
	for name, c := range map[string]struct{ key, hash string }{
		"no stored hash":        {key.Key, ""},
		"no key":                {"", key.Hash},
		"both empty":            {"", ""},
		"another key":           {other.Key, key.Hash},
		"another hash":          {key.Key, other.Hash},
		"extra character":       {key.Key + "x", key.Hash},
		"newline":               {key.Key + "\n", key.Hash},
		"leading space":         {" " + key.Key, key.Hash},
		"truncated":             {key.Key[:len(key.Key)-1], key.Hash},
		"upper-cased":           {strings.ToUpper(key.Key), key.Hash},
		"key as its own hash":   {key.Key, key.Key},
		"hash as the key":       {key.Hash, key.Hash},
		"id only":               {key.ID, key.Hash},
		"one megabyte":          {strings.Repeat("A", 1<<20), key.Hash},
		"NUL bytes":             {"\x00\x00\x00", key.Hash},
		"hash of one with NULs": {key.Key, "\x00"},
	} {
		if mod.Verify(c.key, c.hash) {
			t.Errorf("%s: verified", name)
		}
	}
}

// TestParseIDRejectsMalformedKeys checks the step before the database lookup:
// whatever is not a key never becomes a lookup value.
func TestParseIDRejectsMalformedKeys(t *testing.T) {
	mod := newModule(t)
	key, _ := mod.Generate()

	id, err := mod.ParseID(key.Key)
	if err != nil || id != key.ID {
		t.Fatalf("ParseID of a good key: %q %v", id, err)
	}
	for name, bad := range map[string]string{
		"empty": "", "not a key": "not-a-key", "spaces": "   ", "id without secret": key.ID,
		"newline": key.Key + "\n", "SQL": key.Key + "' OR '1'='1", "NUL": "ak_\x00",
		"unicode": "ak_\u00fcn\u00ef-\u00e7\u00f8d\u00e9", "one megabyte": strings.Repeat("A", 1<<20),
	} {
		got, err := mod.ParseID(bad)
		if err == nil {
			t.Errorf("%s: accepted as id %q", name, got)
			continue
		}
		if !errors.Is(err, apikey.ErrInvalidKey) {
			t.Errorf("%s: error %v is not ErrInvalidKey", name, err)
		}
		if got != "" {
			t.Errorf("%s: returned id %q with an error", name, got)
		}
	}
}
