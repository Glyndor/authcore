package totp

import "errors"

// Sentinel errors returned by the totp package.
// Use errors.Is to check for these in calling code.
var (
	// ErrInvalidConfig is returned by New when the provided Config fails
	// validation (e.g. SkewSteps above 10, RecoveryCodeCount out of range).
	//
	// Safety: INTERNAL, a startup or programming error. Treat as a 500.
	ErrInvalidConfig = errors.New("totp: invalid configuration")

	// ErrInvalidSecret is returned by Verify when the presented secret is not
	// base32 or does not decode to exactly 20 bytes. Secrets minted by Enroll
	// always qualify, so for those it means the stored value was corrupted or
	// truncated. A secret carried over from another implementation is refused
	// too unless it is 160 bits: enroll the user again instead.
	//
	// Safety: INTERNAL — do not echo back to the client.
	ErrInvalidSecret = errors.New("totp: invalid base32 secret")

	// ErrMalformedCode is returned by Verify when the candidate code is not
	// exactly six decimal digits. Distinct from ErrInvalidCode so the caller
	// can tell apart "the code shape is wrong" from "the code is the right
	// shape but does not match".
	//
	// Safety: CLIENT-SAFE — both cases are the same outcome to the user
	// (reject), but the distinction is useful for logs and for rate-limiting
	// policies that want to count malformed inputs separately.
	ErrMalformedCode = errors.New("totp: code must be six decimal digits")

	// ErrInvalidCode is returned by Verify when the candidate code has the
	// right shape (six digits) but does not match any time step in the
	// verification window.
	//
	// Safety: CLIENT-SAFE — return a generic "unauthorized" to the client.
	ErrInvalidCode = errors.New("totp: code does not match")

	// ErrCodeReused is returned by Verify when the recorder reports that the
	// matched step was already accepted, and by VerifyStep when the step is
	// less than or equal to lastUsedStep. It is the module's only signal that
	// a code was presented twice: a replayed stolen code produces it, and so
	// does a user who submits the same code twice. Log it and refuse the
	// attempt; do not revoke the factor on it alone.
	//
	// Safety: CLIENT-SAFE, the caller chooses the response. The user-visible
	// message is normally the same as ErrInvalidCode to avoid telling an
	// attacker the code was once valid, but the caller MUST log this case
	// distinctly because it is the signal that a stolen code was tried.
	ErrCodeReused = errors.New("totp: code already used")

	// ErrStepRecorderRequired is returned by Verify when the supplied
	// StepRecorder is nil. A nil recorder means the caller has not wired
	// step storage, and accepting it would silently disable replay refusal.
	// A caller that manages the step itself uses VerifyStep instead.
	//
	// Safety: INTERNAL, a startup or programming error. Treat as a 500.
	ErrStepRecorderRequired = errors.New("totp: a StepRecorder is required")

	// ErrNotInitialised is returned by every method of a TOTP that New did
	// not build: a zero value has no pepper, and a hash under an empty key
	// is one anyone can compute.
	ErrNotInitialised = errors.New("totp: module not initialised")
)
