package email

import (
	"errors"
	"testing"

	"github.com/Glyndor/authcore/auth/email"
	"github.com/Glyndor/authcore/tests/hostile/identity/hostiletest"
)

// A local part that is not valid UTF-8 is refused, so distinct inputs cannot
// share one canonical address.
func TestHostile_Email_invalidUTF8InTheLocalPartIsRefused(t *testing.T) {
	m := hostiletest.NewEmail(t)
	for _, in := range []string{"al\xffice@example.com", "al\xfeice@example.com", "\xff@example.com"} {
		if got, err := m.ValidateAndNormalize(in); err == nil || !errors.Is(err, email.ErrInvalidEmail) {
			t.Errorf("%q was accepted as %q", in, got)
		}
	}
}
