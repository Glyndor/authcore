package domain

import (
	"errors"
	"testing"

	"github.com/Glyndor/authcore/auth/email"
	"github.com/Glyndor/authcore/tests/hostile/identity/hostiletest"
)

// A domain that is not valid UTF-8 is refused. IDNA reads each bad byte as
// U+FFFD, so before this check every one of them became the same ASCII name,
// which the next validation then refused: distinct inputs shared one canonical
// form and the stored form was not a fixed point.
func TestHostile_Email_invalidUTF8InTheDomainIsRefused(t *testing.T) {
	m := hostiletest.NewEmail(t)
	for b := 0x80; b <= 0xff; b++ {
		in := "a@" + string([]byte{byte(b)}) + ".com"
		if got, err := m.ValidateAndNormalize(in); err == nil || !errors.Is(err, email.ErrInvalidEmail) {
			t.Errorf("byte %#x in the domain: accepted as %q, %v", b, got, err)
		}
	}
	for _, in := range []string{"a@ex\xc3\x28mple.com", "a@\xe2\x82.com", "a@example.\xff", "a@\xed\xa0\x80.com", "a@b\xf0\x9f\x98.com"} {
		if got, err := m.ValidateAndNormalize(in); err == nil {
			t.Errorf("%q was accepted as %q", in, got)
		}
	}
}
