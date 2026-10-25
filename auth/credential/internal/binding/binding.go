// Package binding computes the stored hash of a credential token: a keyed
// HMAC-SHA256 that ties the token to the purpose and subject it was minted
// for.
package binding

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash"
)

// Hash returns the keyed HMAC-SHA256 hex digest of purpose, subject and
// token under secret, each length-prefixed with a big-endian uint32.
//
// The length prefix is what makes the encoding unambiguous, and it is not
// interchangeable with a separator byte. An earlier draft joined the fields
// with a 0x00 byte, which works only while no field can contain that byte,
// and a Go string can: (purpose="a\x00b", subject="c") and (purpose="a",
// subject="b\x00c") hashed identically, so a caller whose subject came from
// untrusted input could redeem a token minted for a different pair. That is
// the exact property this module exists to provide. Prefixing by length
// depends on no assumption about the contents.
func Hash(secret []byte, purpose, subject, token string) string {
	mac := hmac.New(sha256.New, secret)
	writeField(mac, purpose)
	writeField(mac, subject)
	writeField(mac, token)
	return hex.EncodeToString(mac.Sum(nil))
}

// writeField writes s to h prefixed by its length as a big-endian uint32.
func writeField(h hash.Hash, s string) {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(s)))
	_, _ = h.Write(n[:])
	_, _ = h.Write([]byte(s))
}
