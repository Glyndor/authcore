package authcore

import "errors"

// Sentinel errors returned by the authcore package.
// Use errors.Is to check for these in calling code.
var (
	// ErrInvalidConfig is returned when the supplied Config fails validation.
	ErrInvalidConfig = errors.New("authcore: invalid configuration")

	// ErrInvalidTimezone is returned when Config.Timezone is nil.
	ErrInvalidTimezone = errors.New("authcore: timezone must not be nil")

	// ErrKeyManager is returned when the key management system fails to
	// initialise, generate, or load cryptographic material.
	ErrKeyManager = errors.New("authcore: key manager failure")
)
