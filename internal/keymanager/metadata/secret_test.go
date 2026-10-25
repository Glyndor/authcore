package metadata

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/binding"
	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/material"
)

func pair(t *testing.T) (ed25519.PublicKey, []byte) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	return pub, secret
}

func TestCheckSecret(t *testing.T) {
	pub, secret := pair(t)
	_, other := pair(t)
	otherPub, _ := pair(t)
	id := material.KeyID(pub)
	bound := &Metadata{Format: 1, KeyID: id, SecretBinding: binding.Compute(pub, secret)}

	cases := []struct {
		name    string
		m       *Metadata
		pub     ed25519.PublicKey
		secret  []byte
		refused bool
	}{
		{"no descriptor", nil, pub, secret, false},
		{"descriptor without binding", &Metadata{Format: 1, KeyID: id}, pub, other, false},
		{"matching secret", bound, pub, secret, false},
		{"another secret", bound, pub, other, true},
		{"rotated key id is left to Sync", bound, otherPub, other, false},
		{"malformed binding", &Metadata{Format: 1, KeyID: id, SecretBinding: "zz"}, pub, secret, true},
	}
	for _, c := range cases {
		err := CheckSecret("dir", c.m, c.pub, c.secret)
		if (err != nil) != c.refused {
			t.Errorf("%s: err = %v, refused = %v", c.name, err, c.refused)
		}
	}
}

func TestCheckSecretErrorNamesNoBinding(t *testing.T) {
	pub, secret := pair(t)
	_, other := pair(t)
	m := &Metadata{Format: 1, KeyID: material.KeyID(pub), SecretBinding: binding.Compute(pub, secret)}
	err := CheckSecret("dir", m, pub, other)
	if err == nil || strings.Contains(err.Error(), m.SecretBinding) {
		t.Fatalf("err = %v", err)
	}
}

// A descriptor written before the binding existed is completed in place, once.
func TestSyncRecordsTheBindingOnAnOlderDescriptor(t *testing.T) {
	dir, m := seedDir(t)
	log := &captureLogger{}

	if err := Sync(dir, m, m.KeyID, "b1", log); err != nil {
		t.Fatal(err)
	}
	got, err := Read(dir)
	if err != nil || got.SecretBinding != "b1" || got.Created != m.Created {
		t.Fatalf("after the first Sync: %+v, %v", got, err)
	}

	path := filepath.Join(dir, layout.FileMetadata)
	before, _ := os.ReadFile(path)
	if err := Sync(dir, got, got.KeyID, "b1", log); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Error("a bound descriptor was rewritten")
	}
}

func TestSyncFollowsARotatedKeyWithItsBinding(t *testing.T) {
	dir, m := seedDir(t)
	if err := Sync(dir, m, m.KeyID, "old", &captureLogger{}); err != nil {
		t.Fatal(err)
	}
	m, _ = Read(dir)
	if err := Sync(dir, m, "ffffffffffffffff", "new", &captureLogger{}); err != nil {
		t.Fatal(err)
	}
	if got, _ := Read(dir); got.SecretBinding != "new" || got.KeyID != "ffffffffffffffff" {
		t.Fatalf("got %+v", got)
	}
}

func TestSyncBindingWriteFailureIsAWarning(t *testing.T) {
	log := &captureLogger{}
	m := &Metadata{Format: 1, KeyID: "abcdef0123456789"}
	if err := Sync(filepath.Join(t.TempDir(), "missing"), m, m.KeyID, "b", log); err != nil {
		t.Fatal(err)
	}
	if len(log.warnings) != 1 {
		t.Fatalf("warnings = %v", log.warnings)
	}
}

func TestSyncBindingFaultIsReturned(t *testing.T) {
	dir, m := seedDir(t)
	sentinel := errors.New("crash")
	withFault(t, func(p string) error {
		if p == "metadata-written" {
			return sentinel
		}
		return nil
	})
	if err := Sync(dir, m, m.KeyID, "b", &captureLogger{}); !errors.Is(err, sentinel) {
		t.Fatalf("err = %v", err)
	}
}
