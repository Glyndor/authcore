// Package hotp computes the six-digit HOTP/TOTP value of RFC 4226 and
// RFC 6238 and compares it in constant time.
package hotp

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // HMAC-SHA1 is the TOTP interoperability baseline; SHA1 collision attacks do not apply to HMAC
	"crypto/subtle"
	"encoding/binary"
	"fmt"
)

// Cryptographic constants fixed by RFC 6238 §1.2 and the otpauth
// interoperability baseline. They are intentionally not configurable.
const (
	Digits   = 6  // every authenticator app assumes this
	TimeStep = 30 // 30-second window
	Algo     = "SHA1"
)

// Matches reports whether code equals the 6-digit TOTP value for step under
// key, comparing in constant time.
func Matches(step uint64, key []byte, code string) bool {
	otp := Generate(key, step)
	return subtle.ConstantTimeCompare([]byte(otp), []byte(code)) == 1
}

// Generate returns the 6-digit decimal TOTP value for step under
// key (RFC 4226 HOTP on an 8-byte big-endian counter).
func Generate(key []byte, step uint64) string {
	mac := hmac.New(sha1.New, key) //nolint:gosec // HMAC-SHA1 is the TOTP interoperability baseline
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], step)
	mac.Write(counter[:])
	sum := mac.Sum(nil)
	// RFC 4226 §5.3 dynamic truncation.
	offset := sum[len(sum)-1] & 0x0F
	truncated := (uint32(sum[offset])&0x7F)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])
	mod := truncated % 1_000_000
	return fmt.Sprintf("%06d", mod)
}

// IsSixDigits reports whether s is exactly six ASCII decimal digits.
func IsSixDigits(s string) bool {
	if len(s) != 6 {
		return false
	}
	for i := 0; i < 6; i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
