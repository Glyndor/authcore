package password

import (
	"testing"

	"github.com/Glyndor/authcore/auth/password/internal/phc"
)

// The ceiling is a multiple of the configured cost, clamped to the absolute
// limits, and the arithmetic cannot overflow at the extremes of the Config.
func TestVerifyCeiling(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		want phc.Params
	}{
		{"minimum", Config{Memory: 8192, Iterations: 1, Parallelism: 1}, phc.Params{Memory: 1048576, Iterations: 8, Parallelism: 8}},
		{"default", DefaultConfig(), phc.Params{Memory: 1048576, Iterations: 20, Parallelism: 16}},
		{"small memory", Config{Memory: 9000, Iterations: 1, Parallelism: 1}, phc.Params{Memory: 1048576, Iterations: 8, Parallelism: 8}},
		// A module configured above the absolute limit still verifies what it writes.
		{"maximum", Config{Memory: phc.MaxMemory, Iterations: phc.MaxIterations, Parallelism: 255}, phc.Params{Memory: phc.MaxMemory, Iterations: 20, Parallelism: 255}},
	}
	for _, tc := range cases {
		if got := tc.cfg.verifyCeiling(); got != tc.want {
			t.Errorf("%s: verifyCeiling = %+v, want %+v", tc.name, got, tc.want)
		}
	}
}

// A hash made with a stronger work factor than the configured one, within the
// ceiling, keeps verifying.
func TestVerifyAcceptsStrongerHashWithinCeiling(t *testing.T) {
	strongMod := fastMod(t, Config{})
	strongMod.cfg.Memory, strongMod.cfg.Iterations, strongMod.cfg.Parallelism = 16*1024, 2, 2
	hash, err := strongMod.Hash("Correct-Horse-9!")
	if err != nil {
		t.Fatal(err)
	}
	weakMod := fastMod(t, Config{})
	weakMod.cfg.Memory, weakMod.cfg.Iterations, weakMod.cfg.Parallelism = 8192, 1, 1
	ok, err := weakMod.Verify("Correct-Horse-9!", hash)
	if err != nil || !ok {
		t.Fatalf("Verify = %v, %v; want true, nil", ok, err)
	}
}
