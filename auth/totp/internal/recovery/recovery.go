// Package recovery mints, normalises and hashes TOTP recovery codes.
package recovery

import (
	"crypto/hmac"
	"crypto/rand" //nolint:gosec // CSPRNG draws for recovery codes
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/hex"
	"strings"
)

// Len is the byte length of a single recovery code CSPRNG draw.
// 10 bytes = 80 bits, formatted as two base32 groups of 8 chars joined
// by a hyphen (e.g. "ABCD1234-EFGH5678").
const Len = 10

// New returns a fresh recovery code in its display form.
func New() (string, error) {
	buf := make([]byte, Len)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return Format(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf)), nil
}

// Hash returns the keyed HMAC-SHA256 hex digest of the normalised form of
// code (no hyphens, no spaces, uppercase), peppered with key. Normalising here
// means Enroll, HashRecoveryCode and VerifyRecoveryCode all hash the same
// byte sequence regardless of how the user typed the code.
func Hash(key []byte, code string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(Normalize(code)))
	return hex.EncodeToString(mac.Sum(nil))
}

// Format inserts a hyphen at the midpoint of an 8-character
// base32 string. 10 raw bytes encode to 16 base32 chars, so the split
// is 8/8: "ABCD1234EFGH5678" -> "ABCD1234-EFGH5678".
func Format(encoded string) string {
	if len(encoded) != 16 {
		return encoded
	}
	return encoded[:8] + "-" + encoded[8:]
}

// Normalize strips hyphens and spaces and uppercases so
// users can read codes off a printout with any grouping.
func Normalize(code string) string {
	var b strings.Builder
	b.Grow(len(code))
	for i := 0; i < len(code); i++ {
		c := code[i]
		switch {
		case c == '-' || c == ' ':
			// drop
		case c >= 'a' && c <= 'z':
			b.WriteByte(c - 32)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// Find reports whether code matches any of storedHashes, scanning every hash
// in constant time, and returns the zero-based index of the match. The
// candidate is the keyed hash of the normalised code, so the spelling the
// user types (hyphens, spaces, case) does not matter.
func Find(key []byte, code string, storedHashes []string) (int, bool) {
	candidate := Hash(key, Normalize(code))
	var matchedIdx int
	var matched byte
	for i, h := range storedHashes {
		if subtle.ConstantTimeCompare([]byte(candidate), []byte(h)) == 1 {
			matched = 1
			matchedIdx = i
		}
	}
	if matched == 0 {
		return 0, false
	}
	return matchedIdx, true
}
