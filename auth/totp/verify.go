package totp

import (
	"context" //nolint:gosec // CSPRNG draws for secrets and recovery codes
	//nolint:gosec // HMAC-SHA1 is the TOTP interoperability baseline; SHA1 collision attacks do not apply to HMAC
)

// VerifyStep checks candidate code against secret for the current time
// step and the configured skew window. It returns the time step the
// code matched on success.
//
// VerifyStep is the low-level primitive. It does not read or write any
// storage: replay refusal is purely a function of the lastUsedStep the
// caller passes in. That is enough for one verifier, but two verifiers
// running against the same enrollment must not call VerifyStep with the
// lastUsedStep they read from the store - they will race, and a single
// stolen code can be accepted by both. The recorder-backed Verify
// exists to close that race: it delegates the compare-and-advance to
// storage that can make the two operations atomic.
//
// # lastUsedStep and the documented hazard
//
// lastUsedStep is the highest step VerifyStep has accepted for this
// enrollment, or 0 for the first call. Any step at or below it is
// refused with ErrCodeReused - even if the code is otherwise valid - so
// passing the value the store held the last time VerifyStep returned
// nil is the single thing that turns a successful verify into a
// single-use verify.
//
// A caller who always passes 0 has NO replay refusal: every code that
// matches the current window is accepted, including codes the user has
// already used. That is correct for a first verification, and the
// documented wrong behaviour for every other. Verify does not expose
// this shape: its signature requires a StepRecorder, and it refuses a
// nil one with ErrStepRecorderRequired at the first call.
//
// Errors:
//
//	totp.ErrInvalidCode   - six digits, matches no step in the window
//	totp.ErrMalformedCode - not six decimal digits
//	totp.ErrInvalidSecret - secret is not base32, or is not 20 bytes decoded
//	totp.ErrCodeReused    - matches a step at or below lastUsedStep
func (t *TOTP) VerifyStep(secret, code string, lastUsedStep uint64) (uint64, error) {
	if t == nil || !t.initialised {
		return 0, ErrNotInitialised
	}
	return t.ver.VerifyStep(secret, code, lastUsedStep)
}

// Verify is the recording entry point: it asks VerifyStep for the matched
// step and, only when the code is acceptable, hands that step to rec for
// an atomic compare-and-advance. The recorder, not this function, owns
// durability and the cross-process guarantee that two concurrent
// submissions of the same code cannot both succeed.
//
// # Order of checks
//
//   - rec == nil or a typed nil recorder (a nil pointer, map, slice, func or
//     chan wrapped in the interface) returns ErrStepRecorderRequired before
//     anything else. The plain "rec == nil" check is not enough on its own:
//     a typed-nil interface value is non-nil, so without the reflection
//     check a recorder stored as "var rec *myRecorder" would slip past the
//     guard and reach RecordIfNewer, where any method call panics. See
//     isNilRecorderValue.
//   - ctx.Err() != nil returns that error unchanged; the recorder is not
//     called.
//   - VerifyStep is called with lastUsedStep=0, so VerifyStep itself
//     cannot refuse for replay. A refusal here means the code shape is
//     wrong, the secret is wrong, or the code is for the wrong window.
//     The recorder is NOT called in any of those cases; Verify reports
//     the failure to the caller and leaves the stored step untouched.
//   - rec.RecordIfNewer is called with the matched step. When it returns
//     ErrCodeReused (or any error wrapping it), Verify returns an error
//     that satisfies errors.Is(err, ErrCodeReused). Any other error is
//     wrapped with "totp: record step:" so the recorder's signal
//     survives, the caller can still tell reuse from a storage failure,
//     and the wrapped chain points back at the recorder's diagnostic.
//
// # Errors:
//
//	totp.ErrStepRecorderRequired - rec is nil or a typed nil; the recorder was not wired
//	totp.ErrMalformedCode        - not six decimal digits
//	totp.ErrInvalidSecret        - secret is not base32 or not 20 bytes decoded
//	totp.ErrInvalidCode          - six digits, matches no step in the window
//	totp.ErrCodeReused           - the recorder refused to advance the step
//	wrapped storage error        - "totp: record step: ..." for any recorder failure that is not ErrCodeReused
//	context.Canceled / DeadlineExceeded - returned unchanged only when ctx was already cancelled
//	                                 before Verify ran. A recorder that returns context.Canceled is
//	                                 wrapped with "totp: record step:" so errors.Is(err, context.Canceled)
//	                                 still holds but == no longer does.
//
// # Example
//
//	rec := totpPostgresRecorder{db: db, enrollmentID: userID}
//	err := totpMod.Verify(ctx, secret, presented, rec)
//	switch {
//	case errors.Is(err, totp.ErrCodeReused):
//	    // Log it and refuse. A double submission of one code also lands here.
//	    log.Warn("totp: replay attempt (user=%s)", userID)
//	    return http.StatusUnauthorized
//	case err != nil:
//	    return http.StatusUnauthorized
//	}
func (t *TOTP) Verify(ctx context.Context, secret, code string, rec StepRecorder) error {
	if t == nil || !t.initialised {
		return ErrNotInitialised
	}
	return t.ver.Verify(ctx, secret, code, rec)
}

// StepRecorder stores, per enrollment, the highest TOTP time step that has
// been accepted, and advances it atomically.
//
// Implementations are bound to one enrollment. The same Recorder instance
// is reused across the lifetime of that enrollment: every Verify call for
// that enrollment must observe the previous accepted step, even when two
// callers race with the same code.
//
// # Contract
//
// RecordIfNewer atomically stores step when it is greater than the step
// already stored for this enrollment, and returns nil. When the stored
// step is equal to or greater than step it stores nothing and returns
// ErrCodeReused. Any other failure, including a missing or revoked
// enrollment, is returned as an error that is not ErrCodeReused.
//
// # Atomicity
//
// The implementation must make the compare and the store one atomic
// operation across every process that verifies for this enrollment. A
// SQL statement of the shape
//
//	UPDATE totp_enrollments
//	   SET last_step = $step
//	 WHERE id = $id
//	   AND active
//	   AND last_step < $step
//
// whose branch is decided by the affected row count, is the model: the
// condition and the write commit together, so two concurrent submissions
// of the same code can never both advance the stored step. An
// implementation that reads, decides in user code and writes later races
// with itself and silently allows replays.
//
// # Durability
//
// RecordIfNewer must not report nil before the store is durable. Verify
// returns nil to its caller only after RecordIfNewer did, and the caller
// treats that as an accepted verification; a step that is reported stored
// and then lost to a crash lets the same code be accepted again.
//
// # Error shape
//
// Return ErrCodeReused (or an error wrapping it) when the stored step is
// equal to or greater than step. Return a distinct error for every other
// failure: connection lost, enrollment revoked, transaction aborted, the
// row missing. Verify propagates those errors to the caller wrapped
// with a "totp: record step:" prefix so the recorder's signal survives
// but the calling code can still distinguish "code was used" from
// "recorder could not record".
type StepRecorder interface {
	// RecordIfNewer atomically advances the stored step for this
	// enrollment to step when step is greater than the stored value,
	// and returns nil. When the stored value is greater than or equal
	// to step the store is left untouched and ErrCodeReused is
	// returned. Any other error (enrollment missing, connection lost,
	// write rejected) is returned unwrapped.
	RecordIfNewer(ctx context.Context, step uint64) error
}
