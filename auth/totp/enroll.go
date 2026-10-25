package totp

import (

	//nolint:gosec // CSPRNG draws for secrets and recovery codes
	//nolint:gosec // HMAC-SHA1 is the TOTP interoperability baseline; SHA1 collision attacks do not apply to HMAC

	"fmt"

	"github.com/Glyndor/authcore/auth/totp/internal/otpauth"
	"github.com/Glyndor/authcore/auth/totp/internal/recovery"
	"github.com/Glyndor/authcore/auth/totp/internal/secret"
)

// Enrollment is the result of Enroll.
//
// Show Secret, URI and RecoveryCodes to the user EXACTLY ONCE - none is
// recoverable afterwards. Persist Secret (the lookup key, base32) and
// RecoveryHashes (the verification material). Never persist the raw
// RecoveryCodes; they must not survive the enrollment request.
type Enrollment struct {
	// Secret is the shared secret in base32 (no padding), the form
	// authenticator apps accept for manual entry.
	Secret string
	// URI is the otpauth:// URI to encode in the QR code the user scans.
	URI string
	// RecoveryCodes are the raw recovery codes, formatted as two base32
	// groups of 8 chars separated by a hyphen. Hand them to the user
	// ONCE; the caller must delete them from memory after display.
	RecoveryCodes []string
	// RecoveryHashes are the corresponding HMAC-SHA256 digests of the
	// raw codes (peppered with the library's refresh secret). Store
	// these and pass them to VerifyRecoveryCode. The mapping is
	// positional: RecoveryHashes[i] is the hash of RecoveryCodes[i].
	RecoveryHashes []string
}

// Enroll generates a fresh shared secret for accountName, an otpauth://
// URI the user's app can scan as a QR code, and a set of recovery codes.
// Returned values must be shown to the user ONCE (URI as QR, RecoveryCodes
// as a printable list). An empty Config.Issuer means the URI is built
// without the issuer parameter and the label, and the authenticator
// displays only the account name.
func (t *TOTP) Enroll(accountName string) (*Enrollment, error) {
	if t == nil || !t.initialised {
		return nil, ErrNotInitialised
	}
	shared, err := secret.New()
	if err != nil {
		return nil, fmt.Errorf("totp: generate secret: %w", err)
	}

	uri := otpauth.URI(t.cfg.Issuer, accountName, shared)

	rawCodes := make([]string, t.cfg.RecoveryCodeCount)
	hashes := make([]string, t.cfg.RecoveryCodeCount)
	for i := 0; i < t.cfg.RecoveryCodeCount; i++ {
		formatted, err := recovery.New()
		if err != nil {
			return nil, fmt.Errorf("totp: generate recovery code: %w", err)
		}
		rawCodes[i] = formatted
		// hashRecoveryCode normalises on the way in, so the stored
		// hash matches what VerifyRecoveryCode computes regardless
		// of how the user typed the code.
		hashes[i] = t.hashRecoveryCode(formatted)
	}

	t.log.Debug("totp: enrolled (account=%q, recovery_codes=%d)", accountName, len(rawCodes))

	return &Enrollment{
		Secret:         shared,
		URI:            uri,
		RecoveryCodes:  rawCodes,
		RecoveryHashes: hashes,
	}, nil
}
