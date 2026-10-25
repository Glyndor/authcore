package field

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"hash"
	"testing"

	"github.com/Glyndor/authcore/auth/field/internal/kdf"
	"github.com/Glyndor/authcore/auth/field/internal/seal"
)

// TestDeriveKey_SeparatesTheTwoKeysFromEachOtherAndFromTheMaster pins key
// separation, which no behavioural test can see.
//
// Encrypt, Decrypt and BlindIndex all keep working if kdf.Key is removed
// and Keys().RefreshSecret() is used directly for both the AES key and the
// index key. Round trips still round trip and indexes still match, so the
// whole suite stays green while one secret is doing three jobs and a
// weakness in any one construction reaches the others.
//
// This is the assertion that goes red instead.
func TestDeriveKey_SeparatesTheTwoKeysFromEachOtherAndFromTheMaster(t *testing.T) {
	t.Parallel()

	master := newFakeProvider(t).Keys().RefreshSecret()

	encKey, err := kdf.Key(master, kdf.EncryptionInfo)
	if err != nil {
		t.Fatalf("kdf.Key(kdf.EncryptionInfo): %v", err)
	}
	idxKey, err := kdf.Key(master, kdf.IndexInfo)
	if err != nil {
		t.Fatalf("kdf.Key(kdf.IndexInfo): %v", err)
	}

	for name, key := range map[string][]byte{"encKey": encKey, "idxKey": idxKey} {
		if len(key) != kdf.KeyLen {
			t.Errorf("%s is %d bytes, want %d", name, len(key), kdf.KeyLen)
		}
		if bytes.Equal(key, master) {
			t.Errorf("%s is the master secret verbatim: the derivation was skipped", name)
		}
	}
	if bytes.Equal(encKey, idxKey) {
		t.Error("encKey and idxKey are the same value: both info labels derive one key")
	}

	// Derivation must be deterministic, or a restart would lose every row.
	again, err := kdf.Key(master, kdf.EncryptionInfo)
	if err != nil {
		t.Fatalf("kdf.Key again: %v", err)
	}
	if !bytes.Equal(encKey, again) {
		t.Error("kdf.Key is not deterministic: existing ciphertexts would not decrypt after a restart")
	}
}

// TestDeriveKey_NewActuallyStoresTheDerivedKeys is the integration pin
// for kdf.Key. The unit test above verifies that kdf.Key produces
// three distinct values from the master secret; this test verifies that
// New stores the derived keys on the Field, not the master secret. A
// sabotage that "leaves kdf.Key in place" but uses the master secret for
// the actual AES key and HMAC key would still pass the unit test, because
// kdf.Key's output is unused. This test catches that.
func TestDeriveKey_NewActuallyStoresTheDerivedKeys(t *testing.T) {
	t.Parallel()
	p := sharedProvider(t)
	master := p.Keys().RefreshSecret()
	f, err := New(p, Config{Context: "email"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	encKey, err := kdf.Key(master, kdf.EncryptionInfo)
	if err != nil {
		t.Fatalf("kdf.Key(kdf.EncryptionInfo): %v", err)
	}
	idxKey, err := kdf.Key(master, kdf.IndexInfo)
	if err != nil {
		t.Fatalf("kdf.Key(kdf.IndexInfo): %v", err)
	}

	const value = "alice@example.com"
	ctxBytes := []byte("email")
	indexMAC := func(key []byte) string {
		m := hmac.New(sha256.New, key)
		writeLengthPrefixed(m, ctxBytes)
		writeLengthPrefixed(m, []byte(value))
		return hex.EncodeToString(m.Sum(nil))
	}

	idx, err := f.BlindIndex(value)
	if err != nil {
		t.Fatalf("BlindIndex: %v", err)
	}
	if idx == indexMAC(master) {
		t.Error("Field.BlindIndex = HMAC(master, value): the index key on the Field is the master secret")
	}
	if idx != indexMAC(idxKey) {
		t.Error("Field.BlindIndex != HMAC(kdf.Key(master, kdf.IndexInfo), value): New stored a different index key")
	}

	ct, err := f.Encrypt(value)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	raw, err := base64.RawStdEncoding.DecodeString(ct)
	if err != nil {
		t.Fatalf("decode ciphertext: %v", err)
	}
	nonce, sealed, aad := raw[:seal.NonceLen], raw[seal.NonceLen:], aadFor(ctxBytes)
	if openGCM(t, master, nonce, sealed, aad) {
		t.Error("Field.Encrypt ciphertext decrypts under AES-GCM keyed by the master secret")
	}
	if !openGCM(t, encKey, nonce, sealed, aad) {
		t.Error("Field.Encrypt ciphertext does not decrypt under AES-GCM keyed by kdf.Key(master, kdf.EncryptionInfo)")
	}
}

// openGCM probes which key New stored on a Field: returns true iff
// nonce/sealed/aad open to "alice@example.com" under AES-GCM keyed by key.
func openGCM(t *testing.T, key, nonce, sealed, aad []byte) bool {
	t.Helper()
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	plain, err := aead.Open(nil, nonce, sealed, aad)
	return err == nil && string(plain) == "alice@example.com"
}

// writeLengthPrefixed and aadFor are the test's own statement of the
// encodings, written out here so the assertions above do not depend on the
// code they check.
func writeLengthPrefixed(h hash.Hash, b []byte) {
	_, _ = h.Write(binary.BigEndian.AppendUint32(nil, uint32(len(b))))
	_, _ = h.Write(b)
}

func aadFor(context []byte) []byte {
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(context))), context...)
}
