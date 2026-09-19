package totp

import (
	"encoding/base32"
	"errors"
	"strings"
	"testing"
)

// TestDecodeSecretRequiresTheFullLength is the regression for a secret of any
// length being accepted as an HMAC key.
//
// The cases are chosen around the trap that made the gap easy to miss. Short
// inputs were already rejected before the length check existed, but only when
// their length was not a multiple of 8, because that is what selected the
// padded encoding and made them malformed. Every case below whose length is a
// multiple of 8 decoded cleanly and was accepted at whatever size it produced,
// so those are the ones that pin the length check rather than the encoding
// heuristic.
func TestDecodeSecretRequiresTheFullLength(t *testing.T) {
	valid := base32.StdEncoding.WithPadding(base32.NoPadding).
		EncodeToString(make([]byte, secretLen))

	cases := []struct {
		name  string
		input string
		want  bool // want accepted
	}{
		{"exactly 20 bytes", valid, true},
		{"5 bytes, length a multiple of 8", "MZXW6YTB", false},
		{"5 bytes of zeroes, length a multiple of 8", "AAAAAAAA", false},
		{"10 bytes, length a multiple of 8", "MZXW6YTBMZXW6YTB", false},
		{"25 bytes, length a multiple of 8", strings.Repeat("A", 40), false},
		{"empty", "", false},
		{"not base32 at all", "!!!!!!!!", false},
		{"far too long", strings.Repeat("A", 4096), false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key, err := decodeSecret(tc.input)
			switch {
			case tc.want && err != nil:
				t.Fatalf("decodeSecret(%q) = %v, want accepted", tc.input, err)
			case tc.want && len(key) != secretLen:
				t.Fatalf("decodeSecret(%q) returned %d bytes, want %d", tc.input, len(key), secretLen)
			case !tc.want && err == nil:
				t.Fatalf("decodeSecret(%q) accepted a %d-byte key, want ErrInvalidSecret", tc.input, len(key))
			case !tc.want && !errors.Is(err, ErrInvalidSecret):
				t.Fatalf("decodeSecret(%q) = %v, want ErrInvalidSecret", tc.input, err)
			}
		})
	}
}

// TestEnrolledSecretRoundTrips keeps the length check from being tightened
// past what this package itself mints.
func TestEnrolledSecretRoundTrips(t *testing.T) {
	mod := newTOTP(t, Config{})
	enr, err := mod.Enroll("alice@example.com")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	key, err := decodeSecret(enr.Secret)
	if err != nil {
		t.Fatalf("a secret this package minted was rejected: %v", err)
	}
	if len(key) != secretLen {
		t.Errorf("Enroll minted a %d-byte secret, want %d", len(key), secretLen)
	}
}
