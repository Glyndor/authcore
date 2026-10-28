package totp_test

import (
	"runtime"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/totp"
)

// Attacker: a user who chooses their own display name, and with it the account
// label and, in a multi-tenant application, the issuer. Neither has a length
// limit in the module, so the guarantee worth holding is that enrolling costs
// time and memory in proportion to what was sent and the URI stays within the
// escaping of it. The check is a ratio against a smaller input of the same
// shape, not a number from this machine.
func TestHostile_Enroll_provisioningURICostGrowsLinearly(t *testing.T) {
	allocOf := func(f func()) uint64 {
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		f()
		runtime.ReadMemStats(&after)
		return after.TotalAlloc - before.TotalAlloc
	}
	units := map[string]string{
		"plain letters":                "a",
		"bytes that all need escaping": "&=#% ",
		"invalid UTF-8":                "\xff\xfe",
		"three-byte letters":           "\u65e5",
		"a right-to-left override":     "\u202e",
		"a colon, the label separator": ":",
	}
	const small, large = 1 << 16, 1 << 19
	of := func(unit string, n int) string { return strings.Repeat(unit, n/len(unit)) }
	for uname, unit := range units {
		for _, where := range []string{"account", "issuer"} {
			t.Run(where+"/"+uname, func(t *testing.T) {
				enroll := func(n int) (*totp.Enrollment, uint64) {
					m, account := newModule(t), "alice"
					if where == "account" {
						account = of(unit, n)
					} else {
						m = newModule(t, totp.Config{Issuer: of(unit, n)})
					}
					var enr *totp.Enrollment
					got := allocOf(func() {
						var err error
						if enr, err = m.Enroll(account); err != nil {
							t.Errorf("Enroll: %v", err)
						}
					})
					return enr, got
				}
				_, a := enroll(small)
				enr, b := enroll(large)
				if enr == nil {
					return
				}
				// Linear cost is a ratio of 8 here. The bound leaves room for
				// the fixed part (the secret and the recovery codes).
				if b > 12*a {
					t.Errorf("a %d-byte input allocated %d bytes, and a %d-byte one %d: more than linear", large, b, small, a)
				}
				// Every byte is at most three characters of escaped text, and
				// the label and the issuer parameter each carry the issuer.
				if limit := 8 * large; len(enr.URI) > limit {
					t.Errorf("a %d-byte input produced a %d-byte URI, over %d", large, len(enr.URI), limit)
				}
			})
		}
	}
}
