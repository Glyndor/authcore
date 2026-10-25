package strictjson_test

import (
	"errors"
	"testing"

	"github.com/Glyndor/authcore/auth/jwt/internal/jwterr"
	"github.com/Glyndor/authcore/auth/jwt/internal/strictjson"
)

func TestCheck(t *testing.T) {
	known := []string{"exp", "type", "kid"}
	cases := []struct {
		name string
		in   string
		ok   bool
	}{
		{"empty object", `{}`, true},
		{"known names", `{"exp":1,"type":"a"}`, true},
		{"unknown names", `{"role":"a","x":{"role":1,"role":2}}`, true},
		{"nested repeats are not inspected", `{"a":{"b":1,"b":2},"c":[{"d":1,"d":2}]}`, true},
		{"repeated key", `{"type":"a","type":"b"}`, false},
		{"repeated key, equal values", `{"x":1,"x":1}`, false},
		{"repeated key by escape", `{"type":"a","type":"a"}`, false},
		{"known name, other case", `{"EXP":1}`, false},
		{"known name, mixed case", `{"Type":"a"}`, false},
		{"known name, kelvin sign", `{"Kid":"a"}`, false},
		{"unknown names differing by case", `{"role":"a","Role":"b"}`, false},
		{"unknown names differing by long s", `{"s":1,"ſ":2}`, false},
		{"not an object", `[1,1]`, true},
		{"scalar", `"x"`, true},
		{"not json", `{"a":1,`, true},
		{"empty", ``, true},
		{"bad member", `{1:2}`, true},
		{"unterminated value", `{"a":[1,`, true},
	}
	for _, tc := range cases {
		err := strictjson.Check([]byte(tc.in), known...)
		if tc.ok && err != nil {
			t.Errorf("%s: %v, want nil", tc.name, err)
		}
		if !tc.ok && !errors.Is(err, jwterr.ErrTokenMalformed) {
			t.Errorf("%s: %v, want ErrTokenMalformed", tc.name, err)
		}
	}
}
