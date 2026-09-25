package totp

import "fmt"

// Config holds the totp module configuration.
//
// The configuration is split into two layers, matching the authcore
// principle documented in docs/configuration.md:
//
//   - The cryptographic layer is CLOSED and is not configurable here.
//     HMAC-SHA1, 30-second time step, 6-digit codes, 20-byte secrets, and
//     constant-time comparison are the interoperability baseline: every
//     widely-used authenticator app ignores the algorithm, digits and
//     period parameters of an otpauth:// URI and assumes SHA1/6/30, so a
//     configurable value here would produce an enrollment that works in
//     your test environment and locks the user out on their phone.
//   - The policy layer is OPEN with today's value as the default:
//     SkewSteps (clock-skew window), RecoveryCodeCount (how many recovery
//     codes to mint), and Issuer (the label shown in the authenticator).
//
// What stays fixed regardless of configuration:
//
//   - Algorithm: HMAC-SHA1 (RFC 6238 §1.2)
//   - Time step: 30 seconds
//   - Code length: 6 decimal digits
//   - Secret length: 160 bits (20 bytes) per RFC 4226 §4 R1
//   - Secret encoding: base32, no padding, for manual entry
//   - Recovery-code length: 10 bytes (80 bits) per code
//   - Recovery-code hashing: keyed HMAC-SHA256, peppered with the library's
//     managed refresh secret
//   - Comparison discipline: crypto/subtle.ConstantTimeCompare, scanning
//     every entry in the window before returning
//
// Start from DefaultConfig and override only what your installation needs:
//
//	totpMod, err := totp.New(auth, totp.DefaultConfig())
//	totpMod, err := totp.New(auth, totp.Config{SkewSteps: 2})
type Config struct {
	// SkewSteps is the number of time steps either side of the current one
	// that Verify will accept. The total window is 2*SkewSteps+1 steps.
	// A skew of 1 (the default) accepts the current step plus one step on
	// either side - enough to absorb ordinary clock drift between the
	// user's device and the server.
	//
	// Each extra step on either side widens the window a stolen code stays
	// valid in by 30 seconds, so the cap is 10 (5 minutes total). The cap
	// is enforced by validateConfig - larger values are rejected at New().
	//
	// The pointer lets the caller express three states: nil means "keep
	// the default of 1", and an explicit Int(0) means "accept only the
	// current step". A plain int cannot distinguish "unset" from
	// "deliberately zero", and getting that wrong is a lockout rather
	// than a weakening: a caller who left the field alone would silently
	// get no tolerance at all, and every user whose phone clock drifts by
	// a few seconds would fail to sign in.
	//
	// Must not point to a negative value. Defaults to 1.
	SkewSteps *int

	// RecoveryCodeCount is how many recovery codes to mint at enrollment.
	// Recovery codes let a user who has lost their authenticator device
	// regain access to their account by redeeming a one-time code. Each
	// code is 10 random bytes (80 bits) formatted as two base32 groups
	// separated by a hyphen so it can be read off a printout.
	//
	// The minimum is 1 (refused: a single code is not a recovery
	// mechanism). The maximum is 50 (refused: more codes mean a larger
	// hash list to scan on every verification, with negligible user
	// benefit past a small handful).
	//
	// Defaults to 10.
	RecoveryCodeCount int

	// Issuer is the human-readable label of the issuing application shown
	// in the user's authenticator alongside the account name. It is
	// embedded in the otpauth:// URI both as the path prefix and as the
	// "issuer" query parameter.
	//
	// An empty Issuer is allowed: the URI is then built without the issuer
	// parameter and the label, and the authenticator will display only
	// the account name. Set this for every production deployment so users
	// can tell two enrollments with the same account name apart.
	//
	// Defaults to "".
	Issuer string
}

// DefaultConfig returns a Config with the library's recommended defaults.
func DefaultConfig() Config {
	return Config{
		SkewSteps:         Int(1),
		RecoveryCodeCount: 10,
		Issuer:            "",
	}
}

const (
	refreshSecretLen     = 32 // bytes New demands from Keys().RefreshSecret()
	maxSkewSteps         = 10 // 10 steps either side = 5 minutes total window
	minRecoveryCodeCount = 1
	maxRecoveryCodeCount = 50
)

// applyDefaults fills zero-value fields with values from DefaultConfig.
//
// A nil SkewSteps gets the default of one step either side; totp.Int(0)
// is kept, since zero is a meaningful value ("only the current step").
// RecoveryCodeCount=0 is filled with
// the default because no production deployment wants zero recovery
// codes, and the value is range-checked by validateConfig.
func applyDefaults(cfg Config) Config {
	def := DefaultConfig()
	if cfg.RecoveryCodeCount == 0 {
		cfg.RecoveryCodeCount = def.RecoveryCodeCount
	}
	if cfg.SkewSteps == nil {
		cfg.SkewSteps = def.SkewSteps
	}
	return cfg
}

// Int returns a pointer to v, for setting SkewSteps on Config.
//
// SkewSteps is a pointer so that leaving it unset ("keep the default of
// one step either side") stays distinguishable from setting it to zero
// ("accept only the current step"). Without this helper the caller needs
// a temporary local just to take its address:
//
//	zero := 0
//	cfg.SkewSteps = &zero
//
// With it, turning the tolerance window off is one line:
//
//	cfg := totp.DefaultConfig()
//	cfg.SkewSteps = totp.Int(0) // only the current step is accepted
//	mod, err := totp.New(auth, cfg)
//
// This mirrors password.Bool, which exists for the same reason on the
// password policy fields.
func Int(v int) *int { return &v }

// validateConfig returns an error if cfg contains invalid values.
// applyDefaults is always called before validateConfig, so SkewSteps and
// RecoveryCodeCount are guaranteed to be at least their defaults.
func validateConfig(cfg Config) error {
	// applyDefaults always runs first, so SkewSteps is never nil here. The
	// guard is kept so a future caller of validateConfig cannot panic on a
	// raw Config that skipped it.
	if cfg.SkewSteps == nil {
		return fmt.Errorf("skew steps must be set")
	}
	if *cfg.SkewSteps < 0 {
		return fmt.Errorf("skew steps must not be negative, got %d", *cfg.SkewSteps)
	}
	if *cfg.SkewSteps > maxSkewSteps {
		return fmt.Errorf("skew steps must be at most %d, got %d", maxSkewSteps, *cfg.SkewSteps)
	}
	if cfg.RecoveryCodeCount < minRecoveryCodeCount {
		return fmt.Errorf("recovery code count must be at least %d, got %d", minRecoveryCodeCount, cfg.RecoveryCodeCount)
	}
	if cfg.RecoveryCodeCount > maxRecoveryCodeCount {
		return fmt.Errorf("recovery code count must be at most %d, got %d", maxRecoveryCodeCount, cfg.RecoveryCodeCount)
	}
	return nil
}
