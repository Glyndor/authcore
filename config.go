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
	//
	// Ignored when KeyStore is set.
	KeysDir string

	// KeyStore optionally overrides where cryptographic keys come from. When
	// nil (the default), authcore uses the disk store under KeysDir. Set it to
	// source keys from a secret manager, environment, or KMS instead — see
	// NewKeyStoreFromKeys and NewKeyStoreFromPEM. When set, KeysDir is ignored.
	KeyStore KeyStore
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
	// KeysDir only matters for the default disk store; a custom KeyStore does
	// not use it, so skip the directory check entirely.
	if cfg.KeyStore == nil {
		if err := validateKeysDir(cfg.KeysDir); err != nil {
			return err
		}
	}
	return nil
}

// validateKeysDir ensures KeysDir exists (creating it if possible).
//
// It deliberately does NOT probe for writability. A read-only KeysDir is a
// valid and recommended deployment: pre-generated keys mounted read-only into
// a container (see docs/key-management.md). Whether the directory needs to be
// written to depends on whether the key files already exist — that is the key
// manager's concern. When generation is actually required, the key manager
// surfaces a clear write error (wrapped as ErrKeyManager); when the keys are
// already present, no write happens and a read-only mount loads fine.
func validateKeysDir(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("cannot create keys directory %q: %w", dir, err)
	}
	return nil
}
