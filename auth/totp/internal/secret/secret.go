// Package secret mints and decodes the base32 shared secret of a TOTP
// enrollment.
package secret

import (
	"crypto/rand" //nolint:gosec // CSPRNG draw for the shared secret
	"encoding/base32"
	"errors"
)

// Len is the byte length of a shared secret: 160 bits per RFC 4226 §4 R1.
const Len = 20

// ErrInvalid is returned by Decode for every secret it refuses.
var ErrInvalid = errors.New("totp: invalid base32 secret")

// encoding is base32 without padding. Len is 20 bytes, exactly four 40-bit
// base32 groups, so a valid secret encodes to 32 characters either way and
// the padded and unpadded forms are byte-identical.
var encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// New returns a fresh CSPRNG secret in the base32 form authenticator apps
// accept for manual entry.
func New() (string, error) {
	b := make([]byte, Len)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return encoding.EncodeToString(b), nil
}

// maxEncodedLen is the longest base32 input Decode will look at. A 20-byte
// secret encodes to 32 characters unpadded and 32 with padding, since 20 bytes
// is already a whole number of 40-bit base32 groups. The few extra characters
// leave room for nothing in particular and exist so an oversized input is
// refused before it is decoded rather than after.
const maxEncodedLen = 40

// Decode decodes a base32 secret (with or without padding) into raw
// bytes and requires exactly Len of them.
//
// The length check is the point. Before it existed the only size test was
// len(key) == 0, so any secret that decoded to at least one byte was accepted
// and used as an HMAC key: "MZXW6YTB" decodes to 5 bytes, and a 40-bit TOTP
// secret is enumerable. Enroll always mints Len bytes, so nothing this
// package generates was affected; the exposure is a secret arriving from
// outside, migrated from another implementation, pasted by a user, or
// restored from a store that truncated it.
//
// Short inputs did fail before this, which is what made the gap easy to miss,
// but they failed for the wrong reason. The encoding is chosen by
// len(s)%8 != 0, so a length that is not a multiple of 8 gets the padded
// encoding and is rejected as malformed. That reads like a length control and
// is not one: every length that is a multiple of 8 took the unpadded branch
// and decoded cleanly at any size.
func Decode(s string) ([]byte, error) {
	if s == "" || len(s) > maxEncodedLen {
		return nil, ErrInvalid
	}
	// One encoding is enough now, and that is a consequence of the length
	// check rather than a separate decision. Len is 20 bytes, which is
	// exactly four 40-bit base32 groups, so it encodes to 32 characters with
	// no padding and the padded and unpadded forms of a valid secret are
	// byte-identical. The branch that used to switch encodings on
	// len(s)%8 != 0 could therefore no longer produce an accepted result:
	// every input it selected the padded encoding for is one the length check
	// rejects anyway. Measured before removing it.
	key, err := encoding.DecodeString(s)
	if err != nil || len(key) != Len {
		return nil, ErrInvalid
	}
	// The decoder skips "\r" and "\n", so a secret with line breaks decoded
	// to the same key; accept only the spelling Enroll hands out.
	if encoding.EncodeToString(key) != s {
		return nil, ErrInvalid
	}
	return key, nil
}
