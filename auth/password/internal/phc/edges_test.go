package phc_test

import (
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/password/internal/phc"
)

// The parameters Parse accepts are bounded on both sides, and the bounds are
// inclusive: the largest and smallest values the format allows parse, and one
// step outside either end does not. Parse only reads the string, so the 4 GiB
// edge allocates nothing.
func TestParse_parameterBoundsAreInclusive(t *testing.T) {
	salt, key := make([]byte, phc.SaltLen), make([]byte, phc.KeyLen)
	for _, tc := range []struct {
		name   string
		p      phc.Params
		accept bool
	}{
		{"smallest", phc.Params{Memory: phc.MinMemory, Iterations: 1, Parallelism: 1}, true},
		{"largest", phc.Params{Memory: phc.MaxMemory, Iterations: phc.MaxIterations, Parallelism: 255}, true},
		{"memory one below", phc.Params{Memory: phc.MinMemory - 1, Iterations: 1, Parallelism: 1}, false},
		{"memory one above", phc.Params{Memory: phc.MaxMemory + 1, Iterations: 1, Parallelism: 1}, false},
		{"zero iterations", phc.Params{Memory: phc.MinMemory, Iterations: 0, Parallelism: 1}, false},
		{"iterations one above", phc.Params{Memory: phc.MinMemory, Iterations: phc.MaxIterations + 1, Parallelism: 1}, false},
		{"zero lanes", phc.Params{Memory: phc.MinMemory, Iterations: 1, Parallelism: 0}, false},
	} {
		got, _, _, err := phc.Parse(phc.Encode(tc.p, salt, key))
		switch {
		case tc.accept && (err != nil || got != tc.p):
			t.Errorf("%s: Parse = %+v, %v; want %+v, nil", tc.name, got, err, tc.p)
		case !tc.accept && !errors.Is(err, phc.ErrInvalid):
			t.Errorf("%s: Parse err = %v, want ErrInvalid", tc.name, err)
		}
	}
}

// The text of a refusal names what was wrong, so an operator reading a log can
// tell a foreign algorithm from stray bytes in front of the hash.
func TestParse_refusalNamesTheOffendingSegment(t *testing.T) {
	salt, key := make([]byte, phc.SaltLen), make([]byte, phc.KeyLen)
	good := phc.Encode(phc.Params{Memory: phc.MinMemory, Iterations: 1, Parallelism: 1}, salt, key)
	for _, tc := range []struct{ name, in, want string }{
		{"text before the first dollar", "junkpart" + good, strconv.Quote("junkpart")},
		{"foreign algorithm", "$argon2d" + good[len("$argon2id"):], strconv.Quote("argon2d")},
	} {
		_, _, _, err := phc.Parse(tc.in)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want it to quote %s", tc.name, err, tc.want)
		}
	}
}
