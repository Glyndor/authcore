package jwt

import (
	"crypto/ed25519"
	"fmt"
	"strings"
	"time"
)

// Config holds the JWT module configuration.
// All fields have safe defaults; use DefaultConfig() as the starting point.
type Config struct {
	// AccessTokenTTL is the lifetime of access tokens.
	// Defaults to 15 minutes. Capped at 24 hours — longer values risk
	// turning a bearer token into an effectively permanent credential.
	AccessTokenTTL time.Duration

	// RefreshTokenTTL is the lifetime of refresh tokens.
	// Must be strictly greater than AccessTokenTTL.
	// Defaults to 24 hours. Capped at 365 days.
	RefreshTokenTTL time.Duration

	// Issuer is the value of the "iss" claim in every token issued by this
	// module, and the value VerifyAccessToken / RotateTokens require the
	// "iss" claim to match on verification. Tokens whose iss does not equal
	// this string are rejected with ErrTokenInvalid.
	//
	// Defaults to "github.com/Glyndor/authcore".
	// Override this with your own service URL or identifier (e.g. "https://auth.example.com").
	Issuer string

	// Audience is the list of intended recipients embedded in the "aud" claim
	// of every token issued by this module. Verifiers use this to confirm
	// that a token was issued for their service.
	//
	// On verification, only the **first** value (Audience[0]) is enforced.
	// It is snapshotted into a private field at New() time so that a caller
	// who later mutates the slice they passed in cannot panic or weaken the
	// verification path. If you need to accept tokens for multiple audiences
	// today, run one JWT module per audience rather than widening this slice.
	//
	// Defaults to ["github.com/Glyndor/authcore"].
	// Override this with your own service identifiers (e.g. ["https://api.example.com"]).
	Audience []string

	// ClockSkewLeeway is the tolerance applied when validating the "exp" and "iat" claims.
	// It compensates for small clock differences between distributed servers.
	// Defaults to 0 (no leeway). A value of 30 seconds is typical for production deployments.
	// Must not be negative.
	ClockSkewLeeway time.Duration

	// Denylist optionally makes access tokens revocable before they expire.
	// It is nil by default, keeping the stateless fast path (no per-request
	// lookup). Set it to consult your own revocation store on each
	// VerifyAccessToken, keyed by the session jti. See the Denylist type.
	Denylist Denylist

	// PreviousPublicKeys holds Ed25519 public keys that should still be accepted
	// for verification in addition to the current signing key. This is the
	// verification side of zero-downtime key rotation: deploy the new key as the
	// active one and list the old public key here, so tokens already signed by
	// it keep verifying through their lifetime; remove it once they have all
	// expired. New tokens are always signed with the current key only.
	//
	// Empty by default. Each key is indexed by its derived "kid", so a token
	// selects the right key automatically.
	PreviousPublicKeys []ed25519.PublicKey
}

// DefaultConfig returns a Config with safe, production-ready defaults.
//
//	cfg := jwt.DefaultConfig()
//	cfg.AccessTokenTTL   = 5 * time.Minute          // tighten for high-security APIs
//	cfg.Issuer           = "https://auth.example.com"
//	cfg.Audience         = []string{"https://api.example.com"}
//	cfg.ClockSkewLeeway  = 30 * time.Second          // recommended for distributed deployments
//	jwtMod, err := jwt.New[MyClaims](auth, cfg)
func DefaultConfig() Config {
	return Config{
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 24 * time.Hour,
		Issuer:          "github.com/Glyndor/authcore",
		Audience:        []string{"github.com/Glyndor/authcore"},
	}
}

// applyDefaults fills zero-value fields with values from DefaultConfig.
func applyDefaults(cfg Config) Config {
	def := DefaultConfig()
	if cfg.AccessTokenTTL == 0 {
		cfg.AccessTokenTTL = def.AccessTokenTTL
	}
	if cfg.RefreshTokenTTL == 0 {
		cfg.RefreshTokenTTL = def.RefreshTokenTTL
	}
	if cfg.Issuer == "" {
		cfg.Issuer = def.Issuer
	}
	if len(cfg.Audience) == 0 {
		cfg.Audience = def.Audience
	}
	return cfg
}

// maxAccessTokenTTL and maxRefreshTokenTTL cap the configurable token
// lifetimes. They protect operators from accidentally issuing effectively
// permanent bearer tokens (for example by typing 10*time.Hour instead of
// 10*time.Minute). The ceilings match the longest values OWASP's JWT cheat
// sheet recommends for a typical web application.
const (
	maxAccessTokenTTL  = 24 * time.Hour
	maxRefreshTokenTTL = 365 * 24 * time.Hour
)

// validateConfig returns an error if cfg contains invalid or inconsistent values.
func validateConfig(cfg Config) error {
	if cfg.AccessTokenTTL <= 0 {
		return fmt.Errorf("access token TTL must be positive, got %s", cfg.AccessTokenTTL)
	}
	if cfg.AccessTokenTTL > maxAccessTokenTTL {
		return fmt.Errorf("access token TTL must be at most %s, got %s", maxAccessTokenTTL, cfg.AccessTokenTTL)
	}
	if cfg.RefreshTokenTTL <= cfg.AccessTokenTTL {
		return fmt.Errorf(
			"refresh token TTL (%s) must be greater than access token TTL (%s)",
			cfg.RefreshTokenTTL, cfg.AccessTokenTTL,
		)
	}
	if cfg.RefreshTokenTTL > maxRefreshTokenTTL {
		return fmt.Errorf("refresh token TTL must be at most %s, got %s", maxRefreshTokenTTL, cfg.RefreshTokenTTL)
	}
	if len(cfg.Audience) == 0 {
		return fmt.Errorf("audience must contain at least one value")
	}
	// Reject empty or whitespace-only audience entries. A []string{""} passes
	// the length check above but would issue tokens with an empty "aud" and
	// verify against "", silently removing the cross-service-reuse protection
	// the audience claim exists to provide.
	for i, aud := range cfg.Audience {
		if strings.TrimSpace(aud) == "" {
			return fmt.Errorf("audience entry %d must not be empty or whitespace", i)
		}
	}
	if cfg.ClockSkewLeeway < 0 {
		return fmt.Errorf("clock skew leeway must not be negative, got %s", cfg.ClockSkewLeeway)
	}
	for i, pk := range cfg.PreviousPublicKeys {
		if len(pk) != ed25519.PublicKeySize {
			return fmt.Errorf("previous public key %d has wrong length: got %d, want %d", i, len(pk), ed25519.PublicKeySize)
		}
	}
	return nil
}
