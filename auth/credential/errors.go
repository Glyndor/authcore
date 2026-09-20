package credential

import "errors"

// Sentinel errors returned by the credential package.
// Use errors.Is to check for these in calling code.
var (
	// ErrInvalidConfig is returned by New when the provided Config fails
	// validation (e.g. a zero, negative, or oversized TTL).
	//
	// Safety: INTERNAL — a startup/programming error. Treat as a 500.
	ErrInvalidConfig = errors.New("credential: invalid configuration")

	// ErrInvalidCredential is returned by Verify when the presented token does
	// not match the stored hash under the given purpose and subject. A token
	// is the only thing the module ever stored alongside a hash, so a mismatch
	// means either a wrong token or a token minted for a different purpose or
	// subject.
	//
	// Safety: CLIENT-SAFE — return a generic "link invalid or expired" message
	// to the user. The caller MUST show the same generic message for
	// ErrInvalidCredential and ErrExpired because distinguishing them tells an
	// attacker that a token existed.
	ErrInvalidCredential = errors.New("credential: token does not match")

	// ErrExpired is returned by Verify when the token matched the stored hash
	// but its issuedAt is too far in the past (beyond Config.TTL) or too far
	// in the future (more than a minute past clock skew). Both are the same
	// outcome to the user: the link is no longer redeemable.
	//
	// Safety: CLIENT-SAFE — return the same generic message as
	// ErrInvalidCredential. The distinction is for logs and rate-limit
	// accounting, never for the user-visible response.
	ErrExpired = errors.New("credential: token has expired")

	// ErrEmptyPurpose is returned by Issue when the caller passes an empty
	// purpose string. A token minted with an empty purpose would be unbound
	// and could be redeemed against any flow, which is the failure this
	// module exists to prevent.
	//
	// Safety: INTERNAL — a programming error in the calling handler. Do not
	// echo the empty string back; log and return a generic error.
	ErrEmptyPurpose = errors.New("credential: purpose must not be empty")

	// ErrEmptySubject is returned by Issue when the caller passes an empty
	// subject string. A token minted with an empty subject would not be
	// attributable to any user and would be a confused-deputy risk in any
	// "look up by subject" storage.
	//
	// Safety: INTERNAL — a programming error in the calling handler. Do not
	// echo the empty string back; log and return a generic error.
	ErrEmptySubject = errors.New("credential: subject must not be empty")

	// ErrNotInitialised is returned by Issue and Verify on a zero-value
	// Credential (a module that was never constructed by New). Such a
	// module has no HMAC pepper and no clock: issuing would mint a token
	// whose hash anyone can recompute, and verifying would panic.
	//
	// Safety: INTERNAL. The call site that owns the zero value is the one
	// to fix.
	ErrNotInitialised = errors.New("credential: module not initialised")
)
