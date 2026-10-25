// Package blind computes the deterministic blind index of the field module:
// an HMAC-SHA256 over a length-prefixed context and value.
package blind

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash"
)

// Index returns hex(HMAC-SHA256(key, len(context)||context ||
// len(value)||value)), each length a big-endian uint32. The length
// prefix is what makes the encoding unambiguous: ("a", "bc") and
// ("ab", "c") cannot collide, and neither can ("email", "user@x")
// and ("emailuser", "@x"). A separator byte would only disambiguate
// while no field contained it, and a Go string can contain any byte.
func Index(key, context []byte, value string) string {
	mac := hmac.New(sha256.New, key)
	writeLengthPrefixed(mac, context)
	writeLengthPrefixed(mac, []byte(value))
	return hex.EncodeToString(mac.Sum(nil))
}

// writeLengthPrefixed writes b to h prefixed by its length as a
// big-endian uint32. The length prefix is what makes the
// concatenation unambiguous; a separator byte would only hold while
// no field contained it, and a Go string can contain any byte.
func writeLengthPrefixed(h hash.Hash, b []byte) {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(b)))
	_, _ = h.Write(n[:])
	_, _ = h.Write(b)
}
