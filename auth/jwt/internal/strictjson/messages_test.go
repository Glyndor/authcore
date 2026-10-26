package strictjson_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/jwt/internal/jwterr"
	"github.com/Glyndor/authcore/auth/jwt/internal/strictjson"
)

// The error names the clash that was found: a repeated key is reported as
// repeated, and keys that differ only in case as a capitalisation clash.
func TestCheck_errorNamesTheKindOfClash(t *testing.T) {
	cases := []struct {
		name, in, want, notWant string
	}{
		{"repeated key", `{"a":1,"a":2}`, "more than once", "capitalisation"},
		{"repeated escaped key", `{"a":1,"a":2}`, "more than once", "capitalisation"},
		{"case clash", `{"a":1,"A":2}`, "differ only in capitalisation", "more than once"},
		{"kelvin sign clash", `{"k":1,"K":2}`, "differ only in capitalisation", "more than once"},
	}
	for _, c := range cases {
		err := strictjson.Check([]byte(c.in))
		if !errors.Is(err, jwterr.ErrTokenMalformed) {
			t.Errorf("%s: err = %v, want ErrTokenMalformed", c.name, err)
			continue
		}
		if !strings.Contains(err.Error(), c.want) || strings.Contains(err.Error(), c.notWant) {
			t.Errorf("%s: err = %q, want it to mention %q and not %q", c.name, err, c.want, c.notWant)
		}
	}
}
