package totp

import "context"

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
