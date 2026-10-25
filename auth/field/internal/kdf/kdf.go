// Package kdf derives the two keys the field module uses from the library's
// refresh secret: one for AES-256-GCM and one for the blind index.
package kdf

import (
	"crypto/hkdf" //nolint:gosec // standard-library HKDF; sha256 below is per the protocol
	"crypto/sha256"
)

// KeyLen is the derived key size in bytes. 32 bytes is the size AES-256
// requires and the one the derivation produces.
const KeyLen = 32

// HKDF info labels. The version suffix is deliberate: if the
// derivation ever has to change, the old label stays available so
// existing rows remain decryptable. A new label for the new
// construction can sit alongside it in the same code.
const (
	EncryptionInfo = "authcore/field/aes-256-gcm/v1"
	IndexInfo      = "authcore/field/blind-index/v1"
)

// Key runs HKDF-SHA256 over the library-managed refresh secret
// with the given info label and returns KeyLen bytes. Two different
// info labels produce two independent keys, so the encryption key
// and the index key cannot share a weakness even though they are
// both derived from the same 32-byte secret.
func Key(secret []byte, info string) ([]byte, error) {
	return hkdf.Key(sha256.New, secret, nil, info, KeyLen)
}
