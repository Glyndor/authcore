package totp

import (

	//nolint:gosec // CSPRNG draws for secrets and recovery codes
	//nolint:gosec // HMAC-SHA1 is the TOTP interoperability baseline; SHA1 collision attacks do not apply to HMAC

	"github.com/Glyndor/authcore/auth/totp/internal/recovery"
)

// HashRecoveryCode returns the keyed HMAC-SHA256 hex digest of code,
// matching the values stored in Enrollment.RecoveryHashes.
//
// It returns ErrNotInitialised on a zero-value TOTP, whose hash would be
// keyed with nothing.
func (t *TOTP) HashRecoveryCode(code string) (string, error) {
	if t == nil || !t.initialised {
		return "", ErrNotInitialised
	}
	return t.hashRecoveryCode(code), nil
}

// VerifyRecoveryCode reports whether code matches any of storedHashes,
// scanning every hash in constant time. Returns the zero-based index of
// the matched hash and true on success. The caller MUST mark that code
// as used (delete or flag the row) before the next call - otherwise the
// same code can be redeemed repeatedly.
//
// Verification normalises code on the way in (hyphens and spaces are
// stripped, letters are uppercased), so users can read codes off a
// printout with any grouping they like. A code that is empty once normalised
// never matches, not even the hash of the empty code.
func (t *TOTP) VerifyRecoveryCode(code string, storedHashes []string) (int, bool) {
	if t == nil || !t.initialised {
		return 0, false
	}
	return recovery.Find(t.secret, code, storedHashes)
}

// hashRecoveryCode returns the keyed HMAC-SHA256 hex digest of the
// normalised form of code (no hyphens, no spaces, uppercase), peppered
// with the library's managed refresh secret. Normalising here means
// Enroll, HashRecoveryCode and VerifyRecoveryCode all hash the same
// byte sequence regardless of how the user typed the code.
func (t *TOTP) hashRecoveryCode(code string) string {
	return recovery.Hash(t.secret, code)
}
