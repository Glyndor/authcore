package password

import (
	"errors"

	"github.com/Glyndor/authcore/auth/password/internal/policy"
)

// checkPolicy validates plaintext against the policy encoded in cfg. The rules
// live in internal/policy; this adapts the Config, whose *bool fields
// applyDefaults guarantees non-nil, and maps the printable-character reason
// onto the exported ErrNonPrintableCharacter.
func checkPolicy(plaintext string, cfg Config) error {
	err := policy.Check(plaintext, policy.Rules{
		MinLength:     cfg.MinLength,
		MaxLength:     cfg.MaxLength,
		RequireUpper:  *cfg.RequireUpper,
		RequireLower:  *cfg.RequireLower,
		RequireDigit:  *cfg.RequireDigit,
		RequireSymbol: *cfg.RequireSymbol,
	})
	if errors.Is(err, policy.ErrNonPrintable) {
		return ErrNonPrintableCharacter
	}
	return err
}
