package ceiling

import (
	"errors"
	"testing"

	"github.com/Glyndor/authcore/auth/password"
	"github.com/Glyndor/authcore/tests/hostile/password/hostiletest"
)

// The limits New enforces on its own configuration are exact: the value at the
// edge is accepted and the next one is refused with ErrInvalidConfig. New does
// no hashing, so the largest memory setting costs nothing here.
func TestHostile_Ceiling_configEdgesAreExact(t *testing.T) {
	prov := hostiletest.NewProvider(t)
	with := func(edit func(*password.Config)) password.Config {
		cfg := hostiletest.LowCost()
		edit(&cfg)
		return cfg
	}
	for _, tc := range []struct {
		name   string
		cfg    password.Config
		accept bool
	}{
		{"memory floor", with(func(c *password.Config) { c.Memory = 8 * 1024 }), true},
		{"memory below the floor", with(func(c *password.Config) { c.Memory = 8*1024 - 1 }), false},
		{"memory ceiling", with(func(c *password.Config) { c.Memory = 4 * 1024 * 1024 }), true},
		{"memory above the ceiling", with(func(c *password.Config) { c.Memory = 4*1024*1024 + 1 }), false},
		{"iterations ceiling", with(func(c *password.Config) { c.Iterations = 20 }), true},
		{"iterations above the ceiling", with(func(c *password.Config) { c.Iterations = 21 }), false},
		{"min length floor", with(func(c *password.Config) { c.MinLength, c.MaxLength = 8, 64 }), true},
		{"min length below the floor", with(func(c *password.Config) { c.MinLength, c.MaxLength = 7, 64 }), false},
		{"max length ceiling", with(func(c *password.Config) { c.MaxLength = 1024 }), true},
		{"max length above the ceiling", with(func(c *password.Config) { c.MaxLength = 1025 }), false},
		{"max length equal to min length", with(func(c *password.Config) { c.MinLength, c.MaxLength = 20, 20 }), true},
		{"max length below min length", with(func(c *password.Config) { c.MinLength, c.MaxLength = 20, 19 }), false},
	} {
		m, err := password.New(prov, tc.cfg)
		switch {
		case tc.accept && (err != nil || m == nil):
			t.Errorf("%s: New = %v, want success", tc.name, err)
		case !tc.accept && !errors.Is(err, password.ErrInvalidConfig):
			t.Errorf("%s: New = %v, want ErrInvalidConfig", tc.name, err)
		}
	}
}
