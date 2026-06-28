package authcore

import "crypto/ed25519"

// Keys provides read-only access to authcore's managed cryptographic material.
//
// The concrete implementation is *keymanager.KeyManager (internal).
// Sub-modules receive Keys through the Provider interface and must not
// cache or copy the raw key bytes — always call the accessor methods.
type Keys interface {
	// PrivateKey returns the Ed25519 private key used for signing tokens.
	// The caller must not modify the returned slice.
	PrivateKey() ed25519.PrivateKey

	// PublicKey returns the Ed25519 public key used for signature verification.
	// The caller must not modify the returned slice.
	PublicKey() ed25519.PublicKey

	// RefreshSecret returns the 32-byte HMAC-SHA256 key used to hash refresh
	// tokens before they are stored in a database.
	// The caller must not modify the returned slice.
	RefreshSecret() []byte

	// KeyID returns the stable identifier for the current signing key.
	// It is derived from the public key and embedded in the "kid" JOSE header
	// of every issued token so that verifiers can select the correct key when
	// multiple keys are in circulation (e.g. during key rotation).
	KeyID() string
}

// Provider is the narrow interface that *AuthCore satisfies.
//
// Sub-modules must accept a Provider rather than *AuthCore directly.
// This decouples each module from the concrete library type, which has two
// important consequences:
//
//  1. Testability — unit tests can inject a stub Provider without constructing
//     a real AuthCore or touching the file system / network.
//
//  2. Stability — if AuthCore gains new methods in a future release, existing
//     module code is unaffected because it only depends on the methods below.
//
// Guaranteed implementation: *AuthCore.
type Provider interface {
	// Config returns a copy of the active library configuration.
	Config() Config

	// Logger returns the active logger shared across the library.
	// Modules must use this logger rather than creating their own so that
	// all output flows through a single, user-configured sink.
	Logger() Logger

	// Keys returns the library's managed cryptographic material.
	// Sub-modules must call this to obtain signing keys and the refresh secret.
	Keys() Keys
}

// Module is the minimal contract every authcore authentication sub-module must
// implement. It acts as a marker interface today and will grow as shared
// lifecycle requirements (e.g. Close, HealthCheck) are identified.
//
// Available implementations and their concrete constructors:
//
//	auth/jwt      — JSON Web Token authentication (EdDSA / Ed25519)
//	                  jwt.New[T any](p authcore.Provider, cfg jwt.Config) (*jwt.JWT[T], error)
//	auth/password — Argon2id password hashing
//	                  password.New(p authcore.Provider, cfg ...password.Config) (*password.Password, error)
//	auth/email    — email validation, normalization, DNS MX verification
//	                  email.New(p authcore.Provider, cfg ...email.Config) (*email.Email, error)
//	auth/username — username validation, normalization, reserved name blocklist
//	                  username.New(p authcore.Provider) (*username.Username, error)
//
// Conventions shared by every module:
//
//  1. The first argument is always an authcore.Provider (never a concrete *AuthCore).
//  2. Omitting cfg (where variadic) or passing a zero-value Config applies safe,
//     production-ready defaults via each module's applyDefaults helper.
//  3. Constructors return a pointer receiver; concrete types are safe for
//     concurrent use across goroutines after construction completes.
type Module interface {
	// Name returns the unique, lowercase identifier of this module.
	// It must be stable across releases because callers may use it as a key.
	// Examples: "jwt", "apikey", "oauth"
	Name() string
}
