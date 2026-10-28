// Package exhaustion attacks the identity modules with inputs far longer than
// any identity, built from the characters that cost the most to normalise.
package exhaustion

import (
	"runtime"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/tests/hostile/identity/hostiletest"
)

// allocOf reports what f allocated, in bytes.
func allocOf(f func()) uint64 {
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// Attacker: a sign-up form that takes whatever it is sent. The input is far
// over every length limit and made of characters that grow or reorder under
// case mapping, decomposition and IDNA. Forbidden effect: a cost that grows
// faster than the input, so a request of a megabyte costs a hundred times what
// one of a hundred and twenty-eight kilobytes does. The check is a ratio
// against a smaller input of the same shape, so it does not depend on the
// machine, and an absolute ceiling per byte catches a flat regression.
func TestHostile_Exhaustion_costGrowsLinearlyWithTheInput(t *testing.T) {
	em := hostiletest.NewEmail(t)
	un := hostiletest.NewUsername(t)
	targets := map[string]func(s string){
		"email local part": func(s string) { _, _ = em.ValidateAndNormalize(s + "@example.com") },
		"email domain":     func(s string) { _, _ = em.ValidateAndNormalize("a@" + s + ".com") },
		"username":         func(s string) { _, _ = un.ValidateAndNormalize(s) },
	}
	units := map[string]string{
		"a compatibility ligature that expands":   "\ufdfa",
		"a letter with a combining mark":          "e\u0301",
		"a right-to-left override":                "\u202e",
		"a letter that changes length under case": "\u023a",
		"a NUL":                   "\x00",
		"a joined emoji sequence": "\U0001f468\u200d\U0001f469",
		"a full-width letter":     "\uff41",
	}
	const small, large = 1 << 17, 1 << 20
	for tname, run := range targets {
		for uname, unit := range units {
			t.Run(tname+"/"+uname, func(t *testing.T) {
				of := func(n int) string { return strings.Repeat(unit, n/len(unit)+1)[:n/len(unit)*len(unit)] }
				a := allocOf(func() { run(of(small)) })
				b := allocOf(func() { run(of(large)) })
				// Measured on 2026-10-28: a ratio of 8 for linear cost (the
				// input is eight times larger) and at most 32 bytes per byte.
				if b > 12*a {
					t.Errorf("a %d-byte input allocated %d bytes, and a %d-byte one %d: more than linear", large, b, small, a)
				}
				if b > 100*large {
					t.Errorf("a %d-byte input allocated %d bytes, over 100 per byte", large, b)
				}
			})
		}
	}
}
