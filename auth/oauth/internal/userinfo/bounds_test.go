package userinfo

import (
	"errors"
	"strings"
	"testing"
)

func TestCheckShapeBounds(t *testing.T) {
	t.Parallel()
	// An object with n scalar members has 2 + 2n tokens.
	members := func(n int) string {
		return `{` + strings.TrimSuffix(strings.Repeat(`"k":1,`, n), ",") + `}`
	}
	nested := func(n int) string { return strings.Repeat("[", n) + strings.Repeat("]", n) }
	cases := []struct {
		name   string
		body   string
		tooBig bool
	}{
		{"small", `{"id":1}`, false},
		{"scalar", `7`, false},
		{"empty", ``, false},
		{"malformed is left to the decoder", `{"a":`, false},
		{"at the token bound", members((profileMaxTokens - 2) / 2), false},
		{"over the token bound", members((profileMaxTokens-2)/2 + 1), true},
		{"at the depth bound", nested(profileMaxDepth), false},
		{"over the depth bound", nested(profileMaxDepth + 1), true},
		{"trailing data is not walked", `{"a":1}` + strings.Repeat(`{"a":1}`, 50000), false},
	}
	for _, tc := range cases {
		err := checkShape([]byte(tc.body))
		if got := errors.Is(err, errTooLarge); got != tc.tooBig || (err != nil && !got) {
			t.Errorf("%s: err = %v, want too large = %v", tc.name, err, tc.tooBig)
		}
	}
}
