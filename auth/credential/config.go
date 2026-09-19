package credential

import (
	"fmt"
	"time"
)

// Config holds the credential module configuration.
//
// The configuration is split into two layers, matching the authcore
// principle documented in docs/configuration.md:
//
//   - The cryptographic layer is CLOSED and is not configurable here. Token
//     entropy (32 bytes / 256 bits), the HMAC-SHA256 construction and its
//     library-managed pepper, the constant-time comparison, the binding of
//     purpose and subject into the stored hash, and the base64-URL token
//     encoding are fixed. Weakening any of these produces a credential a
//     stolen email can be spent against the wrong user or the wrong flow.
//   - The policy layer is OPEN with today's value as the default: TTL
//     (how long a token remains redeemable).
//
// What stays fixed regardless of configuration:
//
//   - Token length: 32 random bytes (256 bits) per CSPRNG draw
//   - Token encoding: base64 URL without padding, drops into a link as-is
//   - Stored hash: HMAC-SHA256(pepper, len(purpose)||purpose ||
//     len(subject)||subject || len(token)||token), each length a big-endian
//     uint32, so ("reset", "ab") cannot collide with ("reseta", "b") no
//     matter what bytes the fields contain
//   - Hash output: lowercase hex
//   - Comparison: crypto/subtle.ConstantTimeCompare, with the comparison
//     always run before the expiry check so wall-clock time does not reveal
//     whether a token existed
//   - Future issuedAt tolerance: 1 minute, anything more counts as expired
//
// Start from DefaultConfig and override only what your installation needs:
//
//	cred, err := credential.New(auth)                              // defaults
//	cred, err := credential.New(auth, credential.Config{TTL: 15 * time.Minute})
type Config struct {
	// TTL is how long a credential token remains valid from its issuedAt.
	// A reset link that lives longer than a day is a standing key to the
	// account sitting in an inbox, so validateConfig refuses anything above
	// 24 hours. A TTL of zero or a negative TTL is refused for the same
	// reason: an instantly-expired or backwards-running token has no
	// legitimate use, only a bug.
	//
	// Defaults to 1 hour.
	TTL time.Duration
}

// DefaultConfig returns a Config with the library's recommended defaults.
func DefaultConfig() Config {
	return Config{TTL: time.Hour}
}

const maxTTL = 24 * time.Hour

// applyDefaults is a pass-through for TTL.
//
// Unlike auth/totp's SkewSteps (a pointer so zero is a meaningful "no
// tolerance" value), TTL is a plain time.Duration: zero is not
// meaningful (it would make every token instantly expired), so it
// must be refused rather than defaulted. Filling zero with the
// default here would silently turn a caller bug into a 1-hour token,
// so validateConfig is the only thing that decides what TTL values are
// allowed. New routes the no-Config case through DefaultConfig() so
// that callers who omit Config still get the 1-hour default; applyDefaults
// exists only so the function trio (DefaultConfig / applyDefaults /
// validateConfig) matches the shape used across the rest of authcore.
func applyDefaults(cfg Config) Config {
	return cfg
}

// validateConfig returns an error if cfg contains invalid values.
func validateConfig(cfg Config) error {
	if cfg.TTL <= 0 {
		return fmt.Errorf("ttl must be positive, got %s", cfg.TTL)
	}
	if cfg.TTL > maxTTL {
		return fmt.Errorf("ttl must be at most %s, got %s", maxTTL, cfg.TTL)
	}
	return nil
}
