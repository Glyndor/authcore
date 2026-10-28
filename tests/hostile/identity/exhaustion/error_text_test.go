package exhaustion

import (
	"strings"
	"testing"

	"github.com/Glyndor/authcore/tests/hostile/identity/hostiletest"
)

// Attacker: a sign-up form whose rejection is written to a log. The domain is
// invalid and long. Forbidden effect: the refusal repeats the domain, so a
// request of sixty-four kilobytes writes a log line of the same order. The
// check compares the refusal of a long domain with that of a short one of the
// same shape, so it does not depend on the machine or on the wording.
func TestHostile_Exhaustion_domainRefusalTextDoesNotGrowWithTheInput(t *testing.T) {
	em := hostiletest.NewEmail(t)
	shapes := map[string]string{
		"control characters":       "\x00",
		"a bidirectional override": "\u202e",
		"a bidirectional mark":     "\u200f",
		"unassigned code point":    "\U000e0fff",
	}
	for name, unit := range shapes {
		refusal := func(n int) string {
			_, err := em.ValidateAndNormalize("a@" + strings.Repeat(unit, n) + ".com")
			if err == nil {
				t.Fatalf("%s: a domain of %d repeats was accepted", name, n)
			}
			return err.Error()
		}
		short, long := refusal(8), refusal(64<<10)
		if len(long) > 2*len(short)+512 {
			t.Errorf("%s: the refusal grew from %d to %d bytes with the input", name, len(short), len(long))
		}
	}
}
