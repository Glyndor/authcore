package field

import (
	"errors"
	"testing"
)

// Known answers for the stored formats. The index key is HKDF-SHA256 of the
// refresh secret with the label "authcore/field/blind-index/v1", and the
// index is HMAC-SHA256 under it of the length-prefixed context and value;
// that expected value was computed outside Go. The ciphertext was produced
// by this module on 2026-09-25 under the same secret and context, and pins
// the encryption label, the AAD and the nonce placement: a change to any of
// them makes every stored row unreadable, which docs/field.md says the
// version suffix on the labels exists to prevent.
func TestStoredFormats_knownAnswers(t *testing.T) {
	f, err := New(sharedProviderWith([]byte("0123456789abcdef0123456789abcdef")), Config{Context: "email"})
	if err != nil {
		t.Fatal(err)
	}

	idx, err := f.BlindIndex("alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	const wantIdx = "2185adacaeb7191d3ee3841fe7705bfdadd618e1343d9a4bc45cfb4ff82fef37"
	if idx != wantIdx {
		t.Fatalf("BlindIndex = %s, want %s: the index format changed", idx, wantIdx)
	}

	const stored = "7o1DCCNgwG1sHdSxEwFe+lAO8+/Aso+Fmv8+PWUHNNxaCTEUMZmIAFaemL5F"
	plain, err := f.Decrypt(stored)
	if err != nil || plain != "alice@example.com" {
		t.Fatalf("Decrypt of the stored ciphertext = %q, %v: the encryption format changed", plain, err)
	}
	// A trailing byte the decoder refuses is not a spelling of the same
	// ciphertext.
	if _, err := f.Decrypt(stored + "!"); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("Decrypt with a trailing invalid character = %v, want ErrDecrypt", err)
	}
	// A different context does not read it.
	other, err := New(sharedProviderWith([]byte("0123456789abcdef0123456789abcdef")), Config{Context: "phone"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Decrypt(stored); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("Decrypt under another context = %v, want ErrDecrypt", err)
	}
}
