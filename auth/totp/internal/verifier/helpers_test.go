package verifier_test

import (
	"errors"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/totp/internal/hotp"
	"github.com/Glyndor/authcore/auth/totp/internal/secret"
	"github.com/Glyndor/authcore/auth/totp/internal/verifier"
	"github.com/Glyndor/authcore/internal/clock"
)

// The sentinels a Verifier returns are supplied by its caller. These stand in
// for the exported errors of the totp package, under the same names.
var (
	ErrMalformedCode        = errors.New("totp: code is not six decimal digits")
	ErrInvalidSecret        = errors.New("totp: invalid secret")
	ErrInvalidCode          = errors.New("totp: invalid code")
	ErrCodeReused           = errors.New("totp: code already used")
	ErrStepRecorderRequired = errors.New("totp: step recorder required")
)

const (
	timeStep  = hotp.TimeStep
	secretLen = secret.Len
)

func generateTOTP(key []byte, step uint64) string { return hotp.Generate(key, step) }

func decodeSecret(s string) ([]byte, error) { return secret.Decode(s) }

// epoch is a fixed reference time used across tests that need a known
// "now" without sleeping.
var epoch = time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)

// Config carries the one policy field the Verifier reads, with the shape the
// totp package gives it: a pointer, so that nil means the default.
type Config struct {
	SkewSteps *int
}

// Int returns a pointer to v.
func Int(v int) *int { return &v }

// liveClock reads whichever clock the test has most recently installed.
type liveClock func() time.Time

func (f liveClock) Now() time.Time { return f() }

// TOTP is the Verifier under test with a replaceable clock: tests move time
// by assigning to its clock field, as they did on the totp module.
type TOTP struct {
	*verifier.Verifier
	clock clock.Clock
	skew  int
}

// newTOTP creates a Verifier with a fixed clock pinned to epoch and the
// default skew of one step unless cfg says otherwise.
func newTOTP(tb testing.TB, cfg ...Config) *TOTP {
	tb.Helper()
	m := &TOTP{skew: 1, clock: clock.Fixed(epoch)}
	if len(cfg) > 0 && cfg[0].SkewSteps != nil {
		m.skew = *cfg[0].SkewSteps
	}
	m.Verifier = verifier.New(liveClock(func() time.Time { return m.clock.Now() }), m.skew, verifier.Errors{
		Malformed:        ErrMalformedCode,
		InvalidSecret:    ErrInvalidSecret,
		Invalid:          ErrInvalidCode,
		Reused:           ErrCodeReused,
		RecorderRequired: ErrStepRecorderRequired,
	})
	return m
}
