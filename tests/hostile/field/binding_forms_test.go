package field_test

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/Glyndor/authcore/auth/field"
)

// Class: the additional authenticated data and the two derived keys. The module
// binds the context as a 4 byte big-endian length followed by the context. Any
// other way of binding the same context to the same ciphertext is a different
// message to GCM and must be refused, and the encryption key and the index key
// must not be interchangeable.

func TestHostile_Binding_onlyTheLengthPrefixedContextOpens(t *testing.T) {
	const context = "users.email"
	d := newDeployment(t)
	f := d.column(context)
	o := newOracle(t, d.pepper, context)
	nonce := make([]byte, 12)

	le := binary.LittleEndian.AppendUint32(nil, uint32(len(context)))
	wide := binary.BigEndian.AppendUint64(nil, uint64(len(context)))
	for name, aad := range map[string][]byte{
		"nil":                          nil,
		"empty, not nil":               {},
		"the raw context":              []byte(context),
		"little-endian prefix":         append(le, context...),
		"eight byte prefix":            append(wide, context...),
		"prefix only":                  binary.BigEndian.AppendUint32(nil, uint32(len(context))),
		"empty context, with prefix":   binary.BigEndian.AppendUint32(nil, 0),
		"prefix then context then NUL": append(lengthPrefixed([]byte(context)), 0),
		"context then prefix":          append([]byte(context), binary.BigEndian.AppendUint32(nil, uint32(len(context)))...),
		"prefix of a longer context":   lengthPrefixed([]byte(context + "x")),
		"prefix of a shorter context":  lengthPrefixed([]byte(context[:len(context)-1])),
	} {
		forged := o.sealWith(nonce, "secret", aad)
		if got, err := f.Decrypt(forged); got != "" || err != field.ErrDecrypt {
			t.Errorf("%s: a ciphertext bound that way opened: %q, %v", name, got, err)
		}
	}
	// Control: the exact documented form opens.
	if got, err := f.Decrypt(o.sealWith(nonce, "secret", lengthPrefixed([]byte(context)))); err != nil || got != "secret" {
		t.Fatalf("control: %q, %v", got, err)
	}
}

// Two contexts whose raw bytes differ only where the length prefix would be
// read as data cannot be confused: "\x00\x00\x00\x01a" bound under context
// "\x00\x00\x00\x01a" is not the ciphertext of context "a" with an extra prefix.
func TestHostile_Binding_aContextThatLooksLikeAPrefixedContext(t *testing.T) {
	d := newDeployment(t)
	inner := d.column("a")
	outer := d.column(string(lengthPrefixed([]byte("a"))))
	ct, _ := inner.Encrypt("v")
	if got, err := outer.Decrypt(ct); got != "" || err != field.ErrDecrypt {
		t.Errorf("a prefixed-looking context opened another column's value: %q, %v", got, err)
	}
	if mustIndex(t, inner, "v") == mustIndex(t, outer, "v") {
		t.Error("a prefixed-looking context shares a blind index with the column it imitates")
	}
}

// The index key is not the encryption key: sealing with the index key, or
// computing the index with the encryption key, does not interoperate with the
// module.
func TestHostile_Binding_encryptionAndIndexKeysAreNotInterchangeable(t *testing.T) {
	const context = "users.email"
	d := newDeployment(t)
	f := d.column(context)
	o := newOracle(t, d.pepper, context)

	block, _ := aes.NewCipher(o.idxKey)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, 12)
	sealedWithIndexKey := gcm.Seal(nonce, nonce, []byte("v"), o.aad())
	if got, err := f.Decrypt(base64.RawStdEncoding.EncodeToString(sealedWithIndexKey)); got != "" || err != field.ErrDecrypt {
		t.Errorf("a value sealed with the index key opened: %q, %v", got, err)
	}

	mac := hmac.New(sha256.New, o.encKey)
	mac.Write(lengthPrefixed([]byte(context)))
	mac.Write(lengthPrefixed([]byte("v")))
	if hex.EncodeToString(mac.Sum(nil)) == mustIndex(t, f, "v") {
		t.Error("the blind index is computed with the encryption key")
	}
	if string(o.encKey) == string(o.idxKey) {
		t.Error("the two derived keys are equal")
	}
	// Neither key is the pepper itself.
	if string(o.encKey) == string(d.pepper) || string(o.idxKey) == string(d.pepper) {
		t.Error("a derived key equals the refresh secret")
	}
}

// The blind index never equals anything an attacker can compute without the
// secret: an unkeyed SHA-256 of the value or of context||value, in a few
// spellings, is not it.
func TestHostile_Binding_blindIndexIsKeyedNotAPlainHash(t *testing.T) {
	const context = "users.email"
	f := newDeployment(t).column(context)
	idx := mustIndex(t, f, "alice@example.com")
	for name, msg := range map[string][]byte{
		"value":              []byte("alice@example.com"),
		"context then value": []byte(context + "alice@example.com"),
		"prefixed":           append(lengthPrefixed([]byte(context)), lengthPrefixed([]byte("alice@example.com"))...),
		"colon":              []byte(context + ":alice@example.com"),
	} {
		sum := sha256.Sum256(msg)
		if hex.EncodeToString(sum[:]) == idx {
			t.Errorf("the blind index equals an unkeyed SHA-256 of the %s", name)
		}
	}
}
