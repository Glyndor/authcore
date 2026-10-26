package field

import (
	"errors"
	"strings"
	"testing"
)

// Known answers for the stored formats. The index key is HKDF-SHA256 of the
// refresh secret with the label "authcore/field/blind-index/v1", and the
// index is HMAC-SHA256 under it of the length-prefixed context and value;
// that expected value was computed outside Go. The ciphertext was produced
// by this module on 2026-09-25 under the same secret and context, and pins
// the encryption label, the AAD and the nonce placement: a change to any of
// them makes every stored row unreadable, which docs/modules/field.md says the
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

// Decrypt accepts only the spelling Encrypt writes (2026-09-25): a line
// break inside the base64, or different unused bits in its last character,
// decoded to the same bytes and decrypted before.
func TestDecrypt_refusesASecondSpellingOfTheCiphertext(t *testing.T) {
	f, err := New(sharedProvider(t), Config{Context: "email"})
	if err != nil {
		t.Fatal(err)
	}
	ct, err := f.Encrypt("alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := f.Decrypt(ct); err != nil || got != "alice@example.com" {
		t.Fatalf("the ciphertext as written: %q, %v", got, err)
	}
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	i := strings.IndexByte(alphabet, ct[len(ct)-1])
	for name, variant := range map[string]string{
		"line break":      ct[:10] + "\n" + ct[10:],
		"unused bits set": ct[:len(ct)-1] + string(alphabet[i^1]),
	} {
		if variant == ct {
			t.Fatalf("%s: the variant equals the original", name)
		}
		if _, err := f.Decrypt(variant); !errors.Is(err, ErrDecrypt) {
			t.Errorf("%s: %v, want ErrDecrypt", name, err)
		}
	}
}

// TestLengthPrefix_NoCollisionBetweenAdjacentFields is the structural
// guarantee that the length prefix prevents ("a", "bc") from colliding
// with ("ab", "c"). The cases are chosen so a separator-byte
// implementation would collide and the length-prefixed one does not.
// "a||bc" = 0x61 0x62 0x63; "ab||c" = 0x61 0x62 0x63. A separator
// would fold them; the length prefix does not.
func TestLengthPrefix_NoCollisionBetweenAdjacentFields(t *testing.T) {
	p := sharedProvider(t)
	// One context, two different splits of the same byte sequence.
	a, _ := New(p, Config{Context: "a"})
	ab, _ := New(p, Config{Context: "ab"})

	const value = "c" // the "value" is the same, only the context splits
	// a + "bc" vs "ab" + "c": the bytes inside the HMAC are the same,
	// but the framing differs. A separator would collapse them; a
	// length prefix does not.
	idxA, err := a.BlindIndex("bc")
	if err != nil {
		t.Fatalf("BlindIndex: %v", err)
	}
	idxAB, err := ab.BlindIndex(value)
	if err != nil {
		t.Fatalf("BlindIndex: %v", err)
	}
	if idxA == idxAB {
		t.Error("length prefix collision: BlindIndex(\"bc\") under context \"a\" matched BlindIndex(\"c\") under context \"ab\"")
	}
}

// TestLengthPrefix_NoCollisionBetweenContextAndValue is the broader
// version of the same guarantee. We choose a single context "email"
// and a single value "user@x", and another arrangement where the
// combined bytes are the same but the boundary is in a different
// place. A length prefix keeps them apart; a separator would not.
func TestLengthPrefix_NoCollisionBetweenContextAndValue(t *testing.T) {
	p := sharedProvider(t)
	// context "a", value "bc" -> bytes a, b, c
	a, _ := New(p, Config{Context: "a"})
	// context "ab", value "c" -> bytes a, b, c
	ab, _ := New(p, Config{Context: "ab"})

	idxA, err := a.BlindIndex("bc")
	if err != nil {
		t.Fatalf("BlindIndex: %v", err)
	}
	idxAB, err := ab.BlindIndex("c")
	if err != nil {
		t.Fatalf("BlindIndex: %v", err)
	}
	if idxA == idxAB {
		t.Error("length prefix collision: (\"a\",\"bc\") matched (\"ab\",\"c\")")
	}
}

// TestLengthPrefix_NoCollisionSameContextSameValue is the trivial
// sanity check: the same value under the same context must produce
// the same index (already covered above, but listed here for the
// "all four quadrants of the collision matrix" symmetry).
func TestLengthPrefix_NoCollisionSameContextSameValue(t *testing.T) {
	f := newFld(t, "email")
	a, err := f.BlindIndex("alice@example.com")
	if err != nil {
		t.Fatalf("BlindIndex: %v", err)
	}
	b, err := f.BlindIndex("alice@example.com")
	if err != nil {
		t.Fatalf("BlindIndex: %v", err)
	}
	if a != b {
		t.Error("same context, same value produced different indexes")
	}
}

// TestLengthPrefix_NoCollisionWithEmbeddedNULBytes pins the only failure
// mode a length prefix survives that a separator byte does not: a NUL byte
// inside a field. Under a separator-byte implementation the pairing
// ("a\x00b", "c") and ("a", "b\x00c") collapses into the same byte stream.
func TestLengthPrefix_NoCollisionWithEmbeddedNULBytes(t *testing.T) {
	p := sharedProvider(t)
	left, err := New(p, Config{Context: "a\x00b"})
	if err != nil {
		t.Fatalf("New(a\\x00b): %v", err)
	}
	right, err := New(p, Config{Context: "a"})
	if err != nil {
		t.Fatalf("New(a): %v", err)
	}
	idxLeft, err := left.BlindIndex("c")
	if err != nil {
		t.Fatalf("left.BlindIndex: %v", err)
	}
	idxRight, err := right.BlindIndex("b\x00c")
	if err != nil {
		t.Fatalf("right.BlindIndex: %v", err)
	}
	if idxLeft == idxRight {
		t.Error("NUL-byte collision: (\"a\\x00b\",\"c\") and (\"a\",\"b\\x00c\") produced the same index")
	}
}
