package field

import (
	"errors"
	"strings"
	"testing"
)

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
