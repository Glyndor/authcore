package username

import "errors"

// ErrInvalidUsername signals that a username failed validation.
//
// CLIENT-SAFE: the wrapped reason describes exactly which rule failed and is
// suitable for returning in a 400 response:
//
//	normalized, err := usernameMod.ValidateAndNormalize(req.Username)
//	if err != nil {
//	    c.JSON(400, map[string]string{"error": errors.Unwrap(err).Error()})
//	    return
//	}
//
// Use errors.Is to check for this in calling code.
var ErrInvalidUsername = errors.New("username: invalid username")

// usernameViolation wraps ErrInvalidUsername with a single specific reason so
// that both errors.Is(err, ErrInvalidUsername) and errors.Unwrap(err) work correctly.
// Using fmt.Errorf("%w: %w", ...) would create a multi-unwrap error in Go 1.20+
// where errors.Unwrap returns nil, breaking the errors.Unwrap(err).Error() pattern.
type usernameViolation struct{ reason error }

func (v *usernameViolation) Error() string {
	return ErrInvalidUsername.Error() + ": " + v.reason.Error()
}
func (v *usernameViolation) Is(t error) bool { return t == ErrInvalidUsername }
func (v *usernameViolation) Unwrap() error   { return v.reason }
