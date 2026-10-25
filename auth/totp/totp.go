// Package totp provides Time-based One-Time Password (TOTP, RFC 6238)
// authentication for authcore.
//
// TOTP is the algorithm behind the six-digit rotating codes shown by
// Google Authenticator, 1Password, Authy and every other authenticator
// app. authcore enrolls a user by minting a high-entropy shared secret,
// returns an otpauth:// URI that the user's app scans as a QR code, and
// verifies the codes the user subsequently produces - all in constant
// time, with replay protection that the caller wires through a
// StepRecorder.
//
//	auth, _   := authcore.New(authcore.DefaultConfig())
//	totpMod, _ := totp.New(auth)
//
//	// Enroll - show the URI to the user, store secret + recovery hashes.
//	enr, _ := totpMod.Enroll("alice@example.com")
//	db.StoreTOTP(userID, enr.Secret, enr.RecoveryHashes)
//
//	// Verify - the recorder holds the "last accepted step" for this
//	// enrollment and advances it atomically. A nil recorder is a
//	// programming error and is refused with ErrStepRecorderRequired.
//	err := totpMod.Verify(ctx, secret, presented, db.Recorder(userID))
//	if errors.Is(err, totp.ErrCodeReused) {
//	    log.Warn("totp: replay attempt (user=%s)", userID)
//	    return http.StatusUnauthorized
//	}
//	if err != nil { return http.StatusUnauthorized }
//
// # What is fixed and what is open
//
// The cryptographic layer is closed: HMAC-SHA1, 30-second time step,
// 6-digit codes, 20-byte secrets and constant-time comparison are the
// interoperability baseline - every widely-used authenticator app
// ignores the algorithm, digits and period parameters of an otpauth://
// URI and assumes SHA1/6/30. A configurable value here produces an
// enrollment that works in your test environment and locks the user out
// on their phone.
//
// The policy layer is open with secure defaults: the clock-skew window
// (SkewSteps), the number of recovery codes (RecoveryCodeCount) and the
// issuer label (Issuer) can be tuned per deployment without weakening
// the security floor. See docs/guides/configuration.md for the principle.
//
// # Replay protection
//
// A TOTP code stays valid for its whole 30-second window, so an attacker
// who observes one can replay it until the window closes. Verify stops
// that by handing the matched step to a StepRecorder that advances the
// stored step only when it is strictly greater than the one on file.
// Compare and store commit together inside the recorder (a conditional
// UPDATE is the model), so two concurrent submissions of the same code
// cannot both succeed. VerifyStep, the low-level primitive, refuses
// nothing on its own: a caller that passes 0 gets no replay refusal at
// all, which is the documented hazard that forces Verify to require a
// recorder.
package totp

import (

	//nolint:gosec // CSPRNG draws for secrets and recovery codes
	//nolint:gosec // HMAC-SHA1 is the TOTP interoperability baseline; SHA1 collision attacks do not apply to HMAC

	"fmt"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/totp/internal/verifier"
	"github.com/Glyndor/authcore/internal/clock"
)

// Compile-time assertion: *TOTP must satisfy authcore.Module.
var _ authcore.Module = (*TOTP)(nil)

// TOTP is the TOTP module.
//
// Construct one instance at application startup using New and share it
// across goroutines. TOTP is safe for concurrent use after construction.
type TOTP struct {
	cfg    Config
	log    authcore.Logger
	secret []byte             // HMAC-SHA256 pepper for recovery-code hashing
	ver    *verifier.Verifier // owns the injected clock; tests drive it in internal/verifier
	// initialised is set by New as its last act. A zero-value TOTP hashed
	// recovery codes under an empty key, which anyone can compute, until
	// 2026-09-25; every method now refuses on it.
	initialised bool
}

// New creates a TOTP module.
//
// cfg is optional - omit it, or pass a zero-value Config, to apply the
// safe defaults (SkewSteps=1, RecoveryCodeCount=10, Issuer="").
//
//	totpMod, err := totp.New(auth)                      // defaults
//	totpMod, err := totp.New(auth, totp.DefaultConfig()) // explicit
//	totpMod, err := totp.New(auth, totp.Config{Issuer: "Acme"})
//
// SkewSteps is a pointer: nil (the zero Config) means the default of one
// step either side, and totp.Int(0) means only the current step. New copies
// the value, so changing the caller's int afterwards has no effect.
//
// The provider must supply a 32-byte refresh secret, which keys the
// recovery-code hashes.
//
// The module reads the parent AuthCore's logger and refresh secret; it
// generates no key material of its own.
func New(p authcore.Provider, cfg ...Config) (*TOTP, error) {
	if len(cfg) > 1 {
		return nil, fmt.Errorf("%w: at most one Config is allowed, got %d", ErrInvalidConfig, len(cfg))
	}
	if p == nil {
		return nil, fmt.Errorf("%w: provider is nil", ErrInvalidConfig)
	}
	if p.Logger() == nil {
		return nil, fmt.Errorf("%w: provider.Logger() returned nil", ErrInvalidConfig)
	}
	keys := p.Keys()
	if keys == nil {
		return nil, fmt.Errorf("%w: provider.Keys() returned nil", ErrInvalidConfig)
	}
	// An absent or short secret hashed recovery codes under a key anyone can
	// compute; apikey, jwt, field and credential refused it since #425.
	secret := keys.RefreshSecret()
	if l := len(secret); l != refreshSecretLen {
		return nil, fmt.Errorf("%w: refresh secret has wrong length: got %d, want %d", ErrInvalidConfig, l, refreshSecretLen)
	}
	var resolved Config
	if len(cfg) > 0 {
		resolved = applyDefaults(cfg[0])
	} else {
		resolved = DefaultConfig()
	}
	// Copy SkewSteps before validating it. New kept the caller's pointer, so a
	// write through it after New widened the window past maxSkewSteps: at
	// 1,000,000, four of five arbitrary codes verified (measured 2026-09-25).
	resolved.SkewSteps = Int(*resolved.SkewSteps)
	if err := validateConfig(resolved); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}

	t := &TOTP{
		cfg:    resolved,
		log:    p.Logger(),
		secret: secret,
		ver: verifier.New(clock.New(p.Config().Timezone), *resolved.SkewSteps, verifier.Errors{
			Malformed:        ErrMalformedCode,
			InvalidSecret:    ErrInvalidSecret,
			Invalid:          ErrInvalidCode,
			Reused:           ErrCodeReused,
			RecorderRequired: ErrStepRecorderRequired,
		}),
	}
	t.initialised = true
	t.log.Info("totp: module initialised (skew=%d, recovery_codes=%d, issuer=%q)",
		*resolved.SkewSteps, resolved.RecoveryCodeCount, resolved.Issuer)
	return t, nil
}

// Name returns the module's unique identifier. It implements authcore.Module.
func (t *TOTP) Name() string { return "totp" }
