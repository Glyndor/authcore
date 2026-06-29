// Package authcore provides a modular, production-ready authentication library for Go.
//
// # Quick start
//
//	cfg := authcore.DefaultConfig()
//	auth, err := authcore.New(cfg)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// # Modules
//
// Authentication mechanisms live under the auth/ sub-tree. Each module is an
// independent package that accepts an authcore.Provider — the narrow interface
// that *AuthCore satisfies — so modules remain independently testable.
//
//	auth/jwt    — JSON Web Tokens
//	auth/apikey — opaque API key generation and validation
//	auth/oauth  — OAuth 2.0 / OIDC
//
// # Key management
//
// authcore automatically generates and persists cryptographic keys on first
// run. Keys are stored in Config.KeysDir (default ".authcore") and are
// protected by a .gitignore so they are never accidentally committed.
//
// # Extending authcore
//
// To write a new module, accept a Provider in your constructor and implement
// the Module interface:
//
//	type MyModule struct { ... }
//
//	func New(p authcore.Provider, cfg Config) (*MyModule, error) { ... }
//
//	func (m *MyModule) Name() string { return "mymodule" }
package authcore

import (
	"fmt"

	"github.com/Glyndor/authcore/internal/keymanager"
)

// Compile-time proof that *AuthCore satisfies Provider.
// If any method is missing the build fails with a clear message here.
var _ Provider = (*AuthCore)(nil)

// Compile-time proof that *keymanager.KeyManager satisfies Keys.
var _ Keys = (*keymanager.KeyManager)(nil)

// AuthCore is the central object of the library.
// It holds shared configuration, the logger, and the key manager, and is
// the entry point for all authentication sub-modules.
//
// Create one instance per application; it is safe for concurrent use.
type AuthCore struct {
	config Config
	log    Logger
	keys   Keys
}

// New creates and returns a fully initialised *AuthCore.
//
// It applies defaults to any zero-value fields in cfg, validates the result,
// selects or creates a logger, and initialises the key manager.
//
// On first run the key manager creates Config.KeysDir and generates fresh
// Ed25519 keys and an HMAC refresh secret. On subsequent runs the existing
// files are loaded and validated.
//
// New returns a wrapped ErrInvalidConfig on bad configuration, or a wrapped
// ErrKeyManager when key initialisation fails. Both are unwrappable with
// errors.Is.
//
//	// Minimal — all defaults apply.
//	auth, err := authcore.New(authcore.DefaultConfig())
//
//	// Custom keys directory (useful in containers or tests).
//	cfg := authcore.DefaultConfig()
//	cfg.KeysDir = "/run/secrets/authcore"
//	auth, err := authcore.New(cfg)
func New(cfg Config) (*AuthCore, error) {
	cfg = applyDefaults(cfg)

	if err := validateConfig(cfg); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}

	log := newLogger(cfg)

	store := cfg.KeyStore
	if store == nil {
		// Default: the zero-config secure-disk store under KeysDir.
		store = diskKeyStore{dir: cfg.KeysDir, log: log}
	}
	keys, err := store.Load()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrKeyManager, err)
	}

	ac := &AuthCore{
		config: cfg,
		log:    log,
		keys:   keys,
	}

	ac.log.Info("authcore initialised (timezone=%s, logs=%v, keys=%s)",
		cfg.Timezone, cfg.EnableLogs, cfg.KeysDir)

	return ac, nil
}

// Config returns a copy of the active configuration.
// Sub-modules should call this to read shared settings.
func (a *AuthCore) Config() Config {
	return a.config
}

// Logger returns the active Logger.
// Sub-modules must use this logger rather than creating their own so that
// all output flows through a single, user-configured sink.
func (a *AuthCore) Logger() Logger {
	return a.log
}

// Keys returns the library's managed cryptographic material.
// Sub-modules use this to obtain the Ed25519 signing key and the HMAC
// refresh secret without needing direct file-system access.
func (a *AuthCore) Keys() Keys {
	return a.keys
}
