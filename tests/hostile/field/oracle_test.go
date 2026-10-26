package field_test

// An independent implementation of the documented construction, written from
// the package documentation and the standard library only. Tests compare the
// module against it on arbitrary inputs, so a bug that makes the module agree
// with itself (a wrong label, a missing length prefix, a reused key) shows up
// as disagreement with the oracle.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

type oracle struct {
	t       testing.TB
	gcm     cipher.AEAD
	idxKey  []byte
	encKey  []byte
	context string
}

func newOracle(t testing.TB, pepper []byte, context string) *oracle {
	t.Helper()
	encKey, err := hkdf.Key(sha256.New, pepper, nil, "authcore/field/aes-256-gcm/v1", 32)
	if err != nil {
		t.Fatal(err)
	}
	idxKey, err := hkdf.Key(sha256.New, pepper, nil, "authcore/field/blind-index/v1", 32)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(encKey)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	return &oracle{t: t, gcm: gcm, idxKey: idxKey, encKey: encKey, context: context}
}

func lengthPrefixed(b []byte) []byte {
	out := binary.BigEndian.AppendUint32(nil, uint32(len(b)))
	return append(out, b...)
}

func (o *oracle) aad() []byte { return lengthPrefixed([]byte(o.context)) }

// sealWith seals plaintext with an explicit nonce and additional data.
func (o *oracle) sealWith(nonce []byte, plaintext string, aad []byte) string {
	sealed := o.gcm.Seal(append([]byte(nil), nonce...), nonce, []byte(plaintext), aad)
	return base64.RawStdEncoding.EncodeToString(sealed)
}

func (o *oracle) seal(plaintext string) string {
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		o.t.Fatal(err)
	}
	return o.sealWith(nonce, plaintext, o.aad())
}

// open returns the plaintext of a module ciphertext, or false.
func (o *oracle) open(ciphertext string) (string, bool) {
	raw, err := base64.RawStdEncoding.DecodeString(ciphertext)
	if err != nil || len(raw) < 12+16 {
		return "", false
	}
	plain, err := o.gcm.Open(nil, raw[:12], raw[12:], o.aad())
	if err != nil {
		return "", false
	}
	return string(plain), true
}

func (o *oracle) blindIndex(value string) string {
	mac := hmac.New(sha256.New, o.idxKey)
	mac.Write(lengthPrefixed([]byte(o.context)))
	mac.Write(lengthPrefixed([]byte(value)))
	return hex.EncodeToString(mac.Sum(nil))
}
