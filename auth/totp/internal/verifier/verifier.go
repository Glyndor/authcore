// Package verifier checks a presented TOTP code against a shared secret over
// a skew window of time steps, and hands the matched step to a recorder that
// makes replay refusal atomic.
//
// It owns the verification algorithm only. The sentinel errors belong to the
// totp package, which passes its exported values in through Errors so the
// values a caller matches with errors.Is are the ones returned here.
package verifier

import (
	"context"
	"errors"
	"fmt"
	"reflect"

	"github.com/Glyndor/authcore/auth/totp/internal/hotp"
	"github.com/Glyndor/authcore/auth/totp/internal/secret"
	"github.com/Glyndor/authcore/internal/clock"
)

// Recorder is the storage the matched step is handed to. It has the same
// method set as the totp package's StepRecorder, which satisfies it.
type Recorder interface {
	RecordIfNewer(ctx context.Context, step uint64) error
}

// Errors are the sentinel errors a Verifier returns, supplied by the caller.
type Errors struct {
	// Malformed is returned when the code is not six decimal digits.
	Malformed error
	// InvalidSecret is returned when the secret is not base32 or not 20 bytes decoded.
	InvalidSecret error
	// Invalid is returned when the code matches no step in the window.
	Invalid error
	// Reused is returned when the code matches a step at or below the last used one,
	// and is the error a Recorder returns to refuse a step.
	Reused error
	// RecorderRequired is returned when the Recorder is nil or a typed nil.
	RecorderRequired error
}

// Verifier verifies codes against the current time of its clock.
type Verifier struct {
	clock clock.Clock
	skew  uint64
	errs  Errors
}

// New returns a Verifier that reads the time from clk and accepts codes within
// skewSteps time steps either side of the current one.
func New(clk clock.Clock, skewSteps int, errs Errors) *Verifier {
	return &Verifier{clock: clk, skew: uint64(skewSteps), errs: errs}
}

// decodeSecret decodes a base32 secret into its raw bytes and maps every
// refusal onto the InvalidSecret error.
func (v *Verifier) decodeSecret(s string) ([]byte, error) {
	key, err := secret.Decode(s)
	if err != nil {
		return nil, v.errs.InvalidSecret
	}
	return key, nil
}

// VerifyStep checks candidate code against the secret for the current time
// step and the skew window. It returns the time step the code matched on
// success, and refuses a step at or below lastUsedStep with the Reused error.
func (v *Verifier) VerifyStep(encodedSecret, code string, lastUsedStep uint64) (uint64, error) {
	if !hotp.IsSixDigits(code) {
		return 0, v.errs.Malformed
	}
	key, err := v.decodeSecret(encodedSecret)
	if err != nil {
		return 0, err
	}

	currentStep := uint64(v.clock.Now().Unix()) / hotp.TimeStep

	// Scan every step in the window. Never early-return on the first
	// match: that would let an attacker distinguish "matched the
	// current step" from "matched a neighbouring step" by timing.
	var matchedStep uint64
	var matched byte
	skew := v.skew
	// When currentStep is smaller than skew the lower bound wraps to a
	// value near the top of the uint64 range, which is above the upper
	// bound, so the loop body does not run and VerifyStep reports no
	// match. That needs the clock to read within skew steps of the Unix
	// epoch, so it cannot happen in production, and reporting no match
	// is the safe answer when it does. There is no negative step: this
	// is uint64.
	for step := currentStep - skew; step <= currentStep+skew; step++ {
		if hotp.Matches(step, key, code) {
			matched = 1
			matchedStep = step
		}
	}

	if matched == 0 {
		return 0, v.errs.Invalid
	}
	if matchedStep <= lastUsedStep {
		return 0, v.errs.Reused
	}
	return matchedStep, nil
}

// Verify asks VerifyStep for the matched step and, only when the code is
// acceptable, hands that step to rec for an atomic compare-and-advance.
//
// A nil or typed-nil rec returns the RecorderRequired error before anything
// else, and an already cancelled ctx returns its error unchanged. A step rec
// refuses with the Reused error returns that error; any other recorder
// failure is wrapped with "totp: record step:".
func (v *Verifier) Verify(ctx context.Context, encodedSecret, code string, rec Recorder) error {
	if isNilRecorderValue(rec) {
		return v.errs.RecorderRequired
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	step, err := v.VerifyStep(encodedSecret, code, 0)
	if err != nil {
		return err
	}
	switch err := rec.RecordIfNewer(ctx, step); {
	case err == nil:
		return nil
	case errors.Is(err, v.errs.Reused):
		return v.errs.Reused
	default:
		return fmt.Errorf("totp: record step: %w", err)
	}
}

// isNilRecorderValue reports whether the dynamic value held by rec is a nil
// pointer, map, slice, func or chan. A plain "rec == nil" cannot see this:
// an interface holding a typed nil is itself non-nil, so a caller that passes
// "var r *myRecorder" would slip past the guard and reach RecordIfNewer,
// where every method call panics. The same shape is used by the root
// package's isNilValue in internal/keystore.
func isNilRecorderValue(rec Recorder) bool {
	if rec == nil {
		return true
	}
	rv := reflect.ValueOf(rec)
	switch rv.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan:
		return rv.IsNil()
	default:
		return false
	}
}
