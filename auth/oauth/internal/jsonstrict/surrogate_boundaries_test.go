package jsonstrict_test

import (
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth/internal/jsonstrict"
)

func TestWellFormedTextAcceptsExactlyPairedSurrogateEscapes(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, text string
		want       bool
	}{
		{"ordinary escape", `\u0041`, true},
		{"before high range", `\uD7FF`, true},
		{"first high alone", `\uD800`, false},
		{"last high alone", `\uDBFF`, false},
		{"first low alone", `\uDC00`, false},
		{"last low alone", `\uDFFF`, false},
		{"after low range", `\uE000`, true},
		{"first valid pair", `\uD800\uDC00`, true},
		{"last valid pair", `\uDBFF\uDFFF`, true},
		{"low below range", `\uD800\uDBFF`, false},
		{"low above range", `\uD800\uE000`, false},
		{"two low surrogates", `\uDC00\uDC00`, false},
		{"pair then lone low", `\uD800\uDC00\uDC00`, false},
		{"pair then lone high", `\uD800\uDC00\uD800`, false},
		{"pair then ordinary escape", `\uD800\uDC00\u0041`, true},
		{"pair then another pair", `\uD800\uDC00\uDBFF\uDFFF`, true},
		{"missing low backslash", `\uD800xuDC00`, false},
		{"escaped backslash", `\\uD800`, true},
	} {
		for _, lower := range []bool{false, true} {
			text := tc.text
			name := tc.name + "/upper"
			if lower {
				text = strings.ToLower(text)
				name = tc.name + "/lower"
			}
			t.Run(name, func(t *testing.T) {
				raw := []byte(`{"value":"` + text + `"}`)
				if got := jsonstrict.WellFormedText(raw); got != tc.want {
					t.Fatalf("WellFormedText(%s) = %v, want %v", raw, got, tc.want)
				}
			})
		}
	}
}
