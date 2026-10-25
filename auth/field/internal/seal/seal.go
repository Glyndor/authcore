// Package seal encrypts and decrypts one field value with AES-256-GCM,
// binding the column context as additional authenticated data and writing
// the result as unpadded standard base64 of nonce || sealed.
package seal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand" //nolint:gosec // CSPRNG draws for nonces
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	// NonceLen is the GCM standard nonce length. 12 bytes is the value
	// the GCM spec is optimised for and the one the standard library's
	// AES-GCM implementation expects by default.
	NonceLen = 12
	// tagLen is the size of the GCM authentication tag in bytes
	// (the standard library's default). It is appended to the sealed
	// payload and verified on Open.
	tagLen = 16
)

// ErrOpen is returned by Open for every failure mode: an input shorter than
// the nonce, an input that is not the base64 spelling Seal writes, and a
// failed GCM authentication tag. The failures are not distinguished, because
// which one failed is information about the stored data and the caller has
// nothing useful to do differently.
var ErrOpen = errors.New("field: ciphertext cannot be opened")

// Sealer seals and opens values under one key and one bound context. It
// holds no per-call state, so concurrent calls are independent and a fresh
// nonce is drawn on every Seal.
type Sealer struct {
	aead    cipher.AEAD // AES-256-GCM bound to the key
	context []byte      // bound Context as bytes, fed to GCM as AAD
}

// New returns a Sealer over key, which must be a valid AES key, bound to
// context.
func New(key, context []byte) (*Sealer, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("field: new AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("field: new GCM AEAD: %w", err)
	}
	return &Sealer{aead: aead, context: context}, nil
}

// Seal encrypts plaintext and returns the base64-encoded nonce || sealed.
//
// A fresh 12-byte nonce is drawn from crypto/rand on every call, so
// encrypting the same plaintext twice produces different ciphertexts
// and the nonce is never derived from the plaintext (a repeated nonce
// under the same key destroys GCM).
//
// The bound context is fed to GCM as additional authenticated data,
// length-prefixed with a big-endian uint32 so the AAD is unambiguous
// no matter what bytes the context contains.
func (s *Sealer) Seal(plaintext string) (string, error) {
	nonce := make([]byte, NonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("field: generate nonce: %w", err)
	}

	aad := buildAAD(s.context)
	sealed := s.aead.Seal(nonce, nonce, []byte(plaintext), aad)

	return base64.RawStdEncoding.EncodeToString(sealed), nil
}

// Open reverses Seal for a ciphertext that was produced under the same key
// and context. It returns ErrOpen for every failure mode and never panics,
// including on input shorter than the nonce: the base64 decoder would
// otherwise panic on a too-short slice.
func (s *Sealer) Open(ciphertext string) (string, error) {
	raw, err := base64.RawStdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", ErrOpen
	}
	// Accept only the spelling Seal writes. The decoder skips "\r" and
	// "\n" and ignores the unused bits of the last character, so one stored
	// value had several spellings that all decrypted (measured 2026-09-25).
	if base64.RawStdEncoding.EncodeToString(raw) != ciphertext {
		return "", ErrOpen
	}
	if len(raw) < NonceLen+tagLen {
		// Must contain at least nonce + GCM tag; anything shorter
		// cannot possibly be a valid sealed payload. Returning
		// ErrOpen (not panicking) is the whole point of the
		// test "Truncating the ciphertext to shorter than a nonce
		// gives ErrDecrypt, not a panic or an index out of range".
		return "", ErrOpen
	}

	nonce := raw[:NonceLen]
	sealed := raw[NonceLen:]

	aad := buildAAD(s.context)
	plain, err := s.aead.Open(nil, nonce, sealed, aad)
	if err != nil {
		return "", ErrOpen
	}
	return string(plain), nil
}

// buildAAD returns the additional authenticated data: the bound
// Context length-prefixed with a big-endian uint32. AAD is the
// part of the input GCM authenticates but does not encrypt; the
// length prefix makes the encoding unambiguous no matter what
// bytes the Context contains.
func buildAAD(context []byte) []byte {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(context)))
	aad := make([]byte, 0, 4+len(context))
	aad = append(aad, n[:]...)
	aad = append(aad, context...)
	return aad
}
