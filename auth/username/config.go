package username

import (
	"fmt"

	"github.com/Glyndor/authcore/auth/username/internal/reserved"
)

// minLength and maxLength are the library's default length bounds, applied
// when the caller's Config leaves MinLength or MaxLength at the zero value.
// They are a product default - a caller may raise or lower them to fit the
// installation. What is NOT configurable here, because it is the security
// layer, is the character set [a-z0-9_-] (the homoglyph control) and the
// normalization (lowercase + trim). Both stay fixed; widening the character
// set to Unicode is exactly what enables impersonation, so it is closed.
const (
	minLength = 3
	maxLength = 32
)

// upperMaxLength is the absolute ceiling a caller is allowed to set for
// MaxLength. 255 is generous for any reasonable username while still keeping
// storage and lookup columns bounded; anything beyond is almost certainly a
// mistake.
const upperMaxLength = 255

// Config holds the username module's policy options.
//
// Today's behaviour is reproduced by the zero value, so callers that do not
// need to override anything can keep using New(p). NewWithConfig is the
// addition: it takes the policy explicitly.
type Config struct {
	// MinLength is the minimum acceptable username length in bytes.
	// Defaults to 3. Minimum 1; values below that are rejected by
	// validateConfig.
	MinLength int

	// MaxLength is the maximum acceptable username length in bytes.
	// Defaults to 32. Capped at 255.
	MaxLength int

	// ExtraReservedNames adds entries to the built-in reserved-names list.
	// Comparison happens after normalization (lowercase + trim), so the
	// values here are stored in their canonical form.
	ExtraReservedNames []string

	// AllowReservedNames removes entries from the reserved-names set. The
	// built-in blocklist includes names like "support", "info", "test",
	// "home" - a deployment that runs a real "support" account lists it
	// here so the account can be registered. Names are compared after
	// normalization, so values here are stored in canonical form.
	AllowReservedNames []string
}

// DefaultConfig returns a Config that reproduces today's built-in behaviour:
// 3..32 characters, the built-in reserved list, no additions or removals.
func DefaultConfig() Config {
	return Config{
		MinLength: minLength,
		MaxLength: maxLength,
	}
}

// applyDefaults fills zero-value fields with values from DefaultConfig and
// normalizes the two name lists (lowercase + trim) so the rest of the
// package can compare against a single canonical form. The reserved set
// itself is built once at construction time by reservedSet.
func applyDefaults(cfg Config) Config {
	def := DefaultConfig()
	if cfg.MinLength == 0 {
		cfg.MinLength = def.MinLength
	}
	if cfg.MaxLength == 0 {
		cfg.MaxLength = def.MaxLength
	}
	cfg.ExtraReservedNames = normalizeNameList(cfg.ExtraReservedNames)
	cfg.AllowReservedNames = normalizeNameList(cfg.AllowReservedNames)
	return cfg
}

// validateConfig refuses values that are themselves invalid or that would
// make every username fail. The reserved-name lists are not validated here:
// unknown names are simply added or removed as configured.
//
// The returned error wraps ErrInvalidConfig so errors.Is(err, ErrInvalidConfig)
// reports the failure as the documented sentinel, while errors.Unwrap returns
// the specific reason for programmatic handling.
func validateConfig(cfg Config) error {
	switch {
	case cfg.MinLength < 1:
		return &configViolation{reason: fmt.Errorf("min length must be at least 1, got %d", cfg.MinLength)}
	case cfg.MaxLength < cfg.MinLength:
		return &configViolation{reason: fmt.Errorf("max length (%d) must be at least min length (%d)", cfg.MaxLength, cfg.MinLength)}
	case cfg.MaxLength > upperMaxLength:
		return &configViolation{reason: fmt.Errorf("max length must be at most %d, got %d", upperMaxLength, cfg.MaxLength)}
	}
	return nil
}

// reservedSet builds the final reserved-name lookup set from the configured
// additions and removals applied to the built-in list. Names already present
// in ExtraReservedNames are deduped against the built-in list. The result is
// normalised (lowercase + trimmed) so lookups can use the same form
// normalize() produces for the input.
func reservedSet(cfg Config) map[string]struct{} {
	return reserved.Set(cfg.ExtraReservedNames, cfg.AllowReservedNames)
}

// normalizeNameList lowercases and trims every entry. Empty entries are
// dropped so the caller cannot accidentally inject a name that matches
// every input - the normalize() function applied to user input never
// produces the empty string (the validator rejects empty inputs upstream),
// but a misconfigured []string{"  "} would otherwise wedge the set.
func normalizeNameList(names []string) []string {
	out := make([]string, 0, len(names))
	for _, raw := range names {
		n := normalize(raw)
		if n == "" {
			continue
		}
		out = append(out, n)
	}
	return out
}
