package username

import (
	"testing"
	"unicode/utf8"

	"github.com/Glyndor/authcore/tests/hostile/identity/hostiletest"
)

// Whatever the module accepts, normalising its output again must give the same
// text: a stored name that the next lookup rewrites is a name two accounts can
// hold. Every code point of the Basic Multilingual Plane is tried alone, after
// a capital letter and before and after combining marks, because composition
// and case mapping interact only across neighbours.
func TestHostile_Username_acceptedNameIsAFixedPointForEveryBMPRune(t *testing.T) {
	m := hostiletest.NewUsername(t)
	marks := []string{"", "̀", "́", "̈", "̊", "̣", "ͅ"}
	check := func(in string) {
		got, err := m.ValidateAndNormalize(in)
		if err != nil {
			return
		}
		again, err := m.ValidateAndNormalize(got)
		if err != nil || again != got {
			t.Errorf("%+q -> %+q, and again -> %+q, %v", in, got, again, err)
		}
	}
	for r := rune(0x20); r <= 0xffff; r++ {
		if !utf8.ValidRune(r) {
			continue
		}
		for _, mark := range marks {
			check("ab" + string(r) + mark + "cd")
			check("T" + string(r) + mark)
			check(string(r) + mark + "x")
		}
	}
}
