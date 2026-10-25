package kdf

import (
	"bytes"
	"testing"
)

func TestKey_isDeterministicSeparatedByLabelAndNotTheSecret(t *testing.T) {
	master := bytes.Repeat([]byte{0x42}, 32)

	enc, err := Key(master, EncryptionInfo)
	if err != nil {
		t.Fatalf("Key(EncryptionInfo): %v", err)
	}
	idx, err := Key(master, IndexInfo)
	if err != nil {
		t.Fatalf("Key(IndexInfo): %v", err)
	}
	for name, key := range map[string][]byte{"enc": enc, "idx": idx} {
		if len(key) != KeyLen {
			t.Errorf("%s key is %d bytes, want %d", name, len(key), KeyLen)
		}
		if bytes.Equal(key, master) {
			t.Errorf("%s key is the secret verbatim: the derivation was skipped", name)
		}
	}
	if bytes.Equal(enc, idx) {
		t.Error("both labels derive one key")
	}
	again, err := Key(master, EncryptionInfo)
	if err != nil {
		t.Fatalf("Key again: %v", err)
	}
	if !bytes.Equal(enc, again) {
		t.Error("Key is not deterministic: stored rows would not decrypt after a restart")
	}
}

func TestKey_differentSecretsGiveDifferentKeys(t *testing.T) {
	a, err := Key(bytes.Repeat([]byte{1}, 32), IndexInfo)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Key(bytes.Repeat([]byte{2}, 32), IndexInfo)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Error("two secrets derived the same key")
	}
}
