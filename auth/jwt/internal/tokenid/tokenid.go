// Package tokenid generates and recognises the identifiers carried in JWT
// claims: the UUID v7 "jti" and the random "rid" of a refresh token.
package tokenid

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"
)

// IsUUIDv7 reports whether s is a valid UUID v7 string (RFC 9562 §5.7).
// Accepts both upper and lower case — no prior normalization is required,
// removing the implicit dependency on strings.ToLower being called upstream.
//
// UUID canonical form: xxxxxxxx-xxxx-7xxx-[89ab]xxx-xxxxxxxxxxxx (36 chars).
func IsUUIDv7(s string) bool {
	if len(s) != 36 {
		return false
	}
	if s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return false
	}
	// Position 14: version digit must be '7'.
	if s[14] != '7' {
		return false
	}
	// Position 19: variant bits must be 8, 9, a, or b (case-insensitive).
	switch s[19] {
	case '8', '9', 'a', 'b', 'A', 'B':
	default:
		return false
	}
	// All other positions must be hex digits.
	for i := 0; i < 36; i++ {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			continue
		}
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// NewJTI returns a UUID v7 string suitable for use as the "jti" claim.
// The 48-bit timestamp comes from now; the remaining bits are cryptographically random.
//
// Format: xxxxxxxx-xxxx-7xxx-[89ab]xxx-xxxxxxxxxxxx (RFC 9562 §5.7).
func NewJTI(now time.Time) (string, error) {
	ms := now.UnixMilli()

	var b [16]byte
	// Bytes 0-5: 48-bit Unix timestamp in milliseconds.
	b[0] = byte(ms >> 40)
	b[1] = byte(ms >> 32)
	b[2] = byte(ms >> 24)
	b[3] = byte(ms >> 16)
	b[4] = byte(ms >> 8)
	b[5] = byte(ms)

	// Bytes 6-15: random.
	if _, err := rand.Read(b[6:]); err != nil {
		return "", fmt.Errorf("generate token ID: %w", err)
	}

	b[6] = (b[6] & 0x0f) | 0x70 // version 7
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10xx (RFC 4122)

	h := hex.EncodeToString(b[:])
	return fmt.Sprintf("%s-%s-%s-%s-%s", h[0:8], h[8:12], h[12:16], h[16:20], h[20:32]), nil
}

// NewRID returns 16 random bytes encoded as base64.RawURLEncoding (22
// chars, no padding) for the "rid" claim of a refresh token. The value is
// independent of the clock and any other claim; two calls in the same
// wall-clock second produce distinct values with overwhelming probability.
//
// On a crypto/rand failure NewRID wraps the error the same way NewJTI
// does, so callers can propagate it unchanged.
func NewRID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate refresh token RID: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
