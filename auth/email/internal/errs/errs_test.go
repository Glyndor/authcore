package errs_test

import (
	"errors"
	"testing"

	"github.com/Glyndor/authcore/auth/email"
	"github.com/Glyndor/authcore/auth/email/internal/errs"
)

func TestSentinelsAreTheOnesTheFacadeExports(t *testing.T) {
	if email.ErrInvalidEmail != errs.ErrInvalidEmail ||
		email.ErrDomainNoMX != errs.ErrDomainNoMX ||
		email.ErrDomainUnresolvable != errs.ErrDomainUnresolvable {
		t.Fatal("the public sentinels must be the very values errs wraps")
	}
}

func TestWrappersKeepSentinelCauseAndText(t *testing.T) {
	cause := errors.New("boom")
	cases := []struct {
		name     string
		err      error
		sentinel error
		other    error
	}{
		{"Invalid", errs.Invalid(cause), errs.ErrInvalidEmail, errs.ErrDomainNoMX},
		{"Unresolvable", errs.Unresolvable(cause), errs.ErrDomainUnresolvable, errs.ErrDomainNoMX},
		{"NoMX", errs.NoMX(cause), errs.ErrDomainNoMX, errs.ErrDomainUnresolvable},
	}
	for _, c := range cases {
		if !errors.Is(c.err, c.sentinel) {
			t.Errorf("%s: errors.Is must match its sentinel", c.name)
		}
		if errors.Is(c.err, c.other) {
			t.Errorf("%s: must not match an unrelated sentinel", c.name)
		}
		if errors.Unwrap(c.err) != cause {
			t.Errorf("%s: Unwrap must return the cause", c.name)
		}
		if want := c.sentinel.Error() + ": boom"; c.err.Error() != want {
			t.Errorf("%s: Error() = %q, want %q", c.name, c.err.Error(), want)
		}
	}
}
