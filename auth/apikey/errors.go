package apikey

import "errors"

// Sentinel errors returned by the apikey package.
// Use errors.Is to check for these in calling code.
var (
	// ErrInvalidConfig is returned by New when the provided Config fails
	// validation (Prefix longer than 16 characters, contains '_', or
	// contains anything outside [a-z0-9]). An empty Prefix is not an
	// error here: applyDefaults replaces it with DefaultConfig().Prefix
	// ("ak") before validateConfig runs, so Config{Prefix: ""} is
	// accepted and New succeeds with the default prefix.
	//
	// Safety: INTERNAL — a startup/programming error. Treat as a 500.
	ErrInvalidConfig = errors.New("apikey: invalid configuration")

	// ErrInvalidKey is returned by ParseID when the presented key is not a
	// well-formed key for this module (wrong prefix, structure, or id).
	//
	// Safety: INTERNAL — return a generic "unauthorized" to the client; never
	// echo back why the key was rejected.
	ErrInvalidKey = errors.New("apikey: malformed key")

	// ErrNotInitialised is returned by Generate and Hash on a zero-value
	// APIKey (a module that was never constructed by New). A zero-value
	// module carries no HMAC pepper, so calling it would emit output
	// derived from an empty key, a fingerprint no caller asked for.
	//
	// Safety: INTERNAL. The call site that owns the zero value is the one
	// to fix.
	ErrNotInitialised = errors.New("apikey: module not initialised")
)
