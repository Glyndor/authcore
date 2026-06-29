package apikey

import (
	"fmt"
	"strings"
)

// maxPrefixLen bounds the key prefix. A prefix is a short recognisable tag, not
// a payload; capping it keeps keys tidy and scannable.
const maxPrefixLen = 16

// Config holds the apikey module configuration.
type Config struct {
	// Prefix is the fixed tag at the start of every key (e.g. "ak" -> "ak_...").
	// Pick something short and product-specific so a leaked key is recognisable
	// in logs and secret scanners. Must be 1–16 lowercase letters or digits and
	// must not contain "_" (the field separator).
	//
	// Defaults to "ak".
	Prefix string
}

// DefaultConfig returns a Config with safe defaults.
func DefaultConfig() Config {
	return Config{Prefix: "ak"}
}

// applyDefaults fills zero-value fields with values from DefaultConfig.
func applyDefaults(cfg Config) Config {
	if cfg.Prefix == "" {
		cfg.Prefix = DefaultConfig().Prefix
	}
	return cfg
}

// validateConfig returns an error if cfg contains invalid values.
func validateConfig(cfg Config) error {
	if cfg.Prefix == "" {
		return fmt.Errorf("prefix must not be empty")
	}
	if len(cfg.Prefix) > maxPrefixLen {
		return fmt.Errorf("prefix must be at most %d characters, got %d", maxPrefixLen, len(cfg.Prefix))
	}
	if strings.Contains(cfg.Prefix, "_") {
		return fmt.Errorf("prefix must not contain '_' (the key field separator)")
	}
	for _, r := range cfg.Prefix {
		isLower := r >= 'a' && r <= 'z'
		isDigit := r >= '0' && r <= '9'
		if !isLower && !isDigit {
			return fmt.Errorf("prefix must be lowercase letters or digits only, got %q", cfg.Prefix)
		}
	}
	return nil
}
