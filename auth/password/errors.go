package password

import "errors"

// Sentinel errors returned by the password package.
// Use errors.Is to check for these in calling code.
//
// # Error safety
//
// Not all errors are safe to expose in HTTP responses. Follow this guide:
//
//	switch {
//	case errors.Is(err, ErrWeakPassword):
//	    // CLIENT-SAFE: unwrap and show the specific rule that failed.
//	    c.JSON(400, map[string]string{"error": errors.Unwrap(err).Error()})
//	case errors.Is(err, ErrInvalidHash):
//	    // INTERNAL: log the full error, return a generic 500.
//	    log.Printf("hash integrity error: %v", err)
//	    c.JSON(500, map[string]string{"error": "internal server error"})
//	case errors.Is(err, ErrInvalidConfig):
//	    // INTERNAL: programming or startup error — should never reach a handler.
//	    log.Printf("password module misconfigured: %v", err)
//	    c.JSON(500, map[string]string{"error": "internal server error"})
//	}
var (
	// ErrInvalidConfig is returned by New when the provided Config fails
	// validation (e.g. Memory below the minimum).
	//
	// Safety: INTERNAL — do not expose to clients. Treat as a 500.
	ErrInvalidConfig = errors.New("password: invalid config")

	// ErrInvalidHash is returned by Verify when the stored hash is not a
	// valid Argon2id PHC string. This indicates a database integrity problem,
	// not a user error.
	//
	// Safety: INTERNAL — do not expose to clients. Log the full error and
	// return a generic 500. The wrapped message contains implementation details
	// (algorithm name, version numbers) that should not be visible to users.
	ErrInvalidHash = errors.New("password: invalid hash format")

	// ErrWeakPassword is returned by Hash and ValidatePolicy when the plaintext
	// password does not satisfy the built-in policy. The wrapped error contains
	// the specific rule that failed (e.g. "must be at least 12 characters").
	//
	// Safety: CLIENT-SAFE — the wrapped reason is intentional user feedback.
	// Use errors.Unwrap(err).Error() to obtain just the reason without the
	// "password: does not meet policy requirements: " prefix.
	ErrWeakPassword = errors.New("password: does not meet policy requirements")
)

// policyViolation wraps ErrWeakPassword with a single specific reason so that
// both errors.Is(err, ErrWeakPassword) and errors.Unwrap(err) work correctly.
// Using fmt.Errorf("%w: %w", ...) would create a multi-unwrap error in Go 1.20+
// where errors.Unwrap returns nil, breaking the errors.Unwrap(err).Error() pattern.
type policyViolation struct{ reason error }

func (v *policyViolation) Error() string   { return ErrWeakPassword.Error() + ": " + v.reason.Error() }
func (v *policyViolation) Is(t error) bool { return t == ErrWeakPassword }
func (v *policyViolation) Unwrap() error   { return v.reason }
