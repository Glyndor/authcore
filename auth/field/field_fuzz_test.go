package field

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"testing"
)

// FuzzDecrypt compares acceptance and plaintext with standard-library AES-GCM.
func FuzzDecrypt(f *testing.F) {
	pepper := []byte("0123456789abcdef0123456789abcdef")
	mod, err := New(fakeProvider{keys: fakeKeys{secret: pepper}}, Config{Context: "email"})
	if err != nil {
		f.Fatalf("field.New: %v", err)
	}

	key, err := hkdf.Key(sha256.New, pepper, nil, "authcore/field/aes-256-gcm/v1", 32)
	if err != nil {
		f.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		f.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		f.Fatal(err)
	}
	aad := append(binary.BigEndian.AppendUint32(nil, 5), "email"...)
	ct, err := mod.Encrypt("alice@example.com")
	if err != nil {
		f.Fatalf("Encrypt: %v", err)
	}
	raw, _ := base64.RawStdEncoding.DecodeString(ct)
	tampered := make([]byte, len(raw))
	copy(tampered, raw)
	tampered[len(tampered)-1] ^= 0xFF

	f.Add(ct)
	f.Add("")
	f.Add("!")
	f.Add("abc")
	f.Add(base64.RawStdEncoding.EncodeToString(tampered))
	f.Add(base64.RawStdEncoding.EncodeToString([]byte{1, 2, 3}))
	f.Add("====not base64====")
	f.Add("eA") // a real base64 string of 1 byte

	f.Fuzz(func(t *testing.T, ciphertext string) {
		raw, decodeErr := base64.RawStdEncoding.DecodeString(ciphertext)
		var want []byte
		var openErr error
		valid := decodeErr == nil && base64.RawStdEncoding.EncodeToString(raw) == ciphertext && len(raw) >= 28
		if valid {
			want, openErr = gcm.Open(nil, raw[:12], raw[12:], aad)
			valid = openErr == nil
		}
		pt, err := mod.Decrypt(ciphertext)
		if (err == nil) != valid || (valid && pt != string(want)) {
			t.Fatalf("Decrypt = %q, %v; reference = %q, accept=%v", pt, err, want, valid)
		}
	})
}

// FuzzEncryptDecrypt drives Encrypt and Decrypt in sequence with
// arbitrary input. The encrypt path draws a fresh nonce and seals;
// the decrypt path must hand back the exact bytes the caller
// produced. Every byte sequence must round trip because the AAD
// only depends on the bound Context, not the plaintext.
func FuzzEncryptDecrypt(f *testing.F) {
	mod, err := New(newFakeProvider(f), Config{Context: "email"})
	if err != nil {
		f.Fatalf("field.New: %v", err)
	}

	// Seed corpus: empty, ASCII, multibyte UTF-8, embedded NUL,
	// invalid UTF-8 byte sequences, and a long string to stress
	// the seal buffers.
	f.Add("")
	f.Add("alice@example.com")
	f.Add("a\x00b")
	f.Add("\xff\xfe\xfd")
	f.Add("\x00")
	f.Add("éèêë 中文 🎉")
	f.Add(string([]byte{0xC3, 0x28, 0xFE, 0xFF}))

	f.Fuzz(func(t *testing.T, plaintext string) {
		ct, err := mod.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("Encrypt(%q) returned error: %v", plaintext, err)
		}
		pt, err := mod.Decrypt(ct)
		if err != nil {
			t.Fatalf("Decrypt(Encrypt(%q)) returned error: %v", plaintext, err)
		}
		if pt != plaintext {
			t.Fatalf("round trip mismatch: Encrypt(%q) -> Decrypt -> %q", plaintext, pt)
		}
	})
}
