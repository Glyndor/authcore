package authcore

import (
	"fmt"
	"os"
	"time"
)

// Config holds the top-level configuration for an AuthCore instance.
// Zero values are replaced by safe defaults via DefaultConfig or applyDefaults.
type Config struct {
	// EnableLogs controls whether the library emits log output.
	// Defaults to true.
	EnableLogs bool

	// Timezone is used for any time-sensitive operations inside the library.
	// Defaults to time.UTC.
	Timezone *time.Location

	// Logger allows callers to inject a custom logging backend
	// (e.g. slog, zap, zerolog). When set, EnableLogs is ignored.
	// If nil and EnableLogs is true, a default stdlib logger is used.
	Logger Logger

	// KeysDir is the directory where authcore creates and stores cryptographic
	// key files (ed25519_private.pem, ed25519_public.pem, refresh_secret.key).
	//
	// Defaults to ".authcore" relative to the current working directory.
	// Use an absolute path in containerised or restricted environments.
	//
	// The directory is created automatically on first use. A .gitignore is
	// written inside it to prevent accidental commits of key material.
	KeysDir string
}

// DefaultConfig returns a Config populated with safe, production-ready defaults.
//
//	cfg := authcore.DefaultConfig()
//	cfg.EnableLogs = false          // disable logs for tests
//	auth, err := authcore.New(cfg)
func DefaultConfig() Config {
	return Config{
		EnableLogs: true,
		Timezone:   time.UTC,
		KeysDir:    ".authcore",
	}
}

// applyDefaults fills zero-value fields in cfg with values from DefaultConfig.
//
// Note on EnableLogs: Go does not distinguish between "caller explicitly set
// false" and "zero value false". For this reason the recommended pattern is
// always to start from DefaultConfig() and override individual fields:
//
//	cfg := authcore.DefaultConfig()
//	cfg.EnableLogs = false   // intentional opt-out
//
// Callers who pass an empty Config{} receive EnableLogs=false (no logs).
// This is a deliberate safe-by-default choice: a library should never
// produce surprise output in an application that did not ask for it.
func applyDefaults(cfg Config) Config {
	if cfg.Timezone == nil {
		cfg.Timezone = time.UTC
	}
	if cfg.KeysDir == "" {
		cfg.KeysDir = ".authcore"
	}
	return cfg
}

// validateConfig returns an error if cfg contains invalid values.
func validateConfig(cfg Config) error {
	if cfg.Timezone == nil {
		return ErrInvalidTimezone
	}
	if err := validateKeysDir(cfg.KeysDir); err != nil {
		return err
	}
	return nil
}

// validateKeysDir ensures KeysDir can be created and written to.
// Catching this early gives a clear error before the key manager tries to
// generate or load key files.
func validateKeysDir(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("cannot create keys directory %q: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".authcore-write-check-*")
	if err != nil {
		return fmt.Errorf("keys directory %q is not writable: %w", dir, err)
	}
	name := tmp.Name()
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("keys directory %q write check failed: %w", dir, err)
	}
	if err := os.Remove(name); err != nil {
		return fmt.Errorf("keys directory %q write check cleanup failed: %w", dir, err)
	}
	return nil
}
