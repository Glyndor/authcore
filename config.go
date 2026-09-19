package authcore

import (
	"errors"
	"fmt"
	"io/fs"
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
	// key files (ed25519_private.pem, ed25519_public.pem, refresh_secret.key),
	// alongside a metadata.json recording the on-disk layout version.
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

	// RequireExistingKeys makes the disk store load-only: authcore.New loads
	// the three key files from KeysDir and never creates, generates, chmods
	// or writes anything there. The zero value (false) leaves the disk store
	// in its writable default state: an empty KeysDir generates a fresh set
	// on the first run.
	//
	// Set this to true in any production deployment that provisions keys
	// once and mounts them into every replica. The failure mode that the
	// flag addresses was reproduced on 2026-09-19: a container recreated
	// without a volume started with new keys and no error, invalidating
	// every issued token, every stored refresh-token and API-key hash, and
	// every auth/field column (whose key derives from refresh_secret.key).
	// A volume that failed to mount or was mounted at the wrong path is the
	// same situation from the load-only path's point of view: an empty
	// KeysDir. RequireExistingKeys turns that silent failure into a startup
	// error.
	//
	// It is ignored when KeyStore is set: a custom KeyStore neither writes
	// nor keys off KeysDir, so the field has nothing to gate.
	//
	// When the disk store is in use and the field is true, New fails with an
	// error wrapping ErrInvalidConfig when KeysDir does not exist or is not a
	// directory. The error names the path and tells the operator to provision
	// the three key files (ed25519_private.pem, ed25519_public.pem,
	// refresh_secret.key) into it: restore them from a backup, or generate
	// them once without this flag and mount the result. New fails with an
	// error wrapping ErrKeyManager when any key file is missing, unreadable,
	// holds malformed material, or the directory has a malformed
	// metadata.json. The same error type a partially-populated directory
	// already produces, so existing handling keeps working.
	//
	// See docs/key-management.md (Load-only in production) and
	// docs/containers.md (the recommended compose file) for the deployment
	// shape this flag is designed for.
	RequireExistingKeys bool
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
	if cfg.KeyStore != nil {
		return nil
	}
	if cfg.RequireExistingKeys {
		// Load-only mode. Do not call validateKeysDir: it runs MkdirAll and
		// would create the directory the operator meant to refuse to start
		// without. A stat-only check is enough: production deployments mount
		// a Secret volume that resolves through symlinks, so follow them.
		return validateLoadOnlyKeysDir(cfg.KeysDir)
	}
	return validateKeysDir(cfg.KeysDir)
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

// validateLoadOnlyKeysDir checks that dir exists and is a directory, without
// creating it. The check uses os.Stat, which follows symlinks: that is what a
// Kubernetes Secret mount needs (the Secret volume is a tree of symlinks).
//
// The zero value of KeysDir is replaced by applyDefaults before validateConfig
// runs in New, so by the time this function is called dir is non-empty.
//
// The error names the path and tells the operator how to recover. It is the
// config-side counterpart of the load-only keymanager error: both messages
// point at restoring the three key files from a backup.
func validateLoadOnlyKeysDir(dir string) error {
	fi, err := os.Stat(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf(
				"key directory %q does not exist; authcore will not generate keys in "+
					"load-only mode. Provision ed25519_private.pem, ed25519_public.pem "+
					"and refresh_secret.key (restore them from a backup, or generate "+
					"them once without Config.RequireExistingKeys set) before starting",
				dir)
		}
		return fmt.Errorf("inspect key directory %q: %w", dir, err)
	}
	if !fi.IsDir() {
		return fmt.Errorf(
			"keys directory %q is a %s, not a directory; load-only mode requires a "+
				"directory holding ed25519_private.pem, ed25519_public.pem and "+
				"refresh_secret.key",
			dir, fi.Mode().Type())
	}
	return nil
}
