package nilvalue_test

import (
	"testing"

	"github.com/Glyndor/authcore/internal/nilvalue"
)

type holder struct{}

func (*holder) Do() {}

type worker interface{ Do() }

func TestIsNil(t *testing.T) {
	t.Parallel()

	var nilPtr *holder
	var nilFunc func()
	var nilMap map[string]int
	var nilSlice []int
	var nilChan chan int
	var nilIface worker
	var typedNil worker = nilPtr

	cases := []struct {
		name string
		v    any
		want bool
	}{
		{"untyped nil", nil, true},
		{"nil interface value", nilIface, true},
		{"typed nil pointer", typedNil, true},
		{"nil pointer", nilPtr, true},
		{"nil function", nilFunc, true},
		{"live pointer", &holder{}, false},
		{"live function", func() {}, false},
		{"struct value", holder{}, false},
		{"integer", 0, false},
		// Methods on a nil map, slice or channel can be valid, so they are
		// not reported.
		{"nil map", nilMap, false},
		{"nil slice", nilSlice, false},
		{"nil channel", nilChan, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := nilvalue.IsNil(c.v); got != c.want {
				t.Fatalf("IsNil(%s) = %v, want %v", c.name, got, c.want)
			}
		})
	}
}
