package secret_test

import (
	"encoding/base32"
	"errors"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/totp"
	"github.com/Glyndor/authcore/auth/totp/internal/secret"
)

// A secret has one spelling: the base32 decoder skips line breaks.
func TestDecodeSecret_refusesLineBreaks(t *testing.T) {
	mod := newTOTP(t)
	enr, err := mod.Enroll("alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := secret.Decode(enr.Secret); err != nil {
		t.Fatalf("the secret as enrolled: %v", err)
	}
	for _, s := range []string{enr.Secret[:8] + "\n" + enr.Secret[8:], enr.Secret[:16] + "\r\n" + enr.Secret[16:]} {
		if _, err := secret.Decode(s); err == nil {
			t.Errorf("%q: Decode accepted a secret with a line break", s)
		}
		if _, err := mod.VerifyStep(s, "123456", 0); !errors.Is(err, totp.ErrInvalidSecret) {
			t.Errorf("%q: %v, want ErrInvalidSecret", s, err)
		}
	}
}

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
//
// Each case is checked twice: Decode refuses it, and the totp module, which
// maps every refusal onto ErrInvalidSecret, reports that sentinel.
func TestDecodeSecretRequiresTheFullLength(t *testing.T) {
	valid := base32.StdEncoding.WithPadding(base32.NoPadding).
		EncodeToString(make([]byte, secret.Len))
	mod := newTOTP(t)

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
			key, err := secret.Decode(tc.input)
			_, stepErr := mod.VerifyStep(tc.input, "123456", 0)
			switch {
			case tc.want && err != nil:
				t.Fatalf("Decode(%q) = %v, want accepted", tc.input, err)
			case tc.want && len(key) != secret.Len:
				t.Fatalf("Decode(%q) returned %d bytes, want %d", tc.input, len(key), secret.Len)
			case tc.want && errors.Is(stepErr, totp.ErrInvalidSecret):
				t.Fatalf("VerifyStep(%q) = %v, want the secret accepted", tc.input, stepErr)
			case !tc.want && err == nil:
				t.Fatalf("Decode(%q) accepted a %d-byte key, want a refusal", tc.input, len(key))
			case !tc.want && !errors.Is(stepErr, totp.ErrInvalidSecret):
				t.Fatalf("VerifyStep(%q) = %v, want ErrInvalidSecret", tc.input, stepErr)
			}
		})
	}
}

// TestEnrolledSecretRoundTrips keeps the length check from being tightened
// past what this package itself mints.
func TestEnrolledSecretRoundTrips(t *testing.T) {
	mod := newTOTP(t, totp.Config{})
	enr, err := mod.Enroll("alice@example.com")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	key, err := secret.Decode(enr.Secret)
	if err != nil {
		t.Fatalf("a secret this package minted was rejected: %v", err)
	}
	if len(key) != secret.Len {
		t.Errorf("Enroll minted a %d-byte secret, want %d", len(key), secret.Len)
	}
}
