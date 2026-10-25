package password_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/Glyndor/authcore/auth/password"
)

// The Verify ceiling is a multiple of the configured cost, so its edges are
// exact: a stored hash at the edge verifies, one step past it is refused before
// any key is derived. The module is configured at the floor (8 MiB, 1 pass,
// 1 lane), where the multiples are 8 passes and 8 lanes.
func TestHostile_Ceiling_edgesAreExactForPassesAndLanes(t *testing.T) {
	m := newModule(t, lowCost())
	salt := []byte("0123456789abcdef")
	for _, tc := range []struct {
		name    string
		mem, it uint32
		par     uint8
		accept  bool
	}{
		{"8 passes, 8 lanes: at the edge", 8192, 8, 8, true},
		{"8 passes, 1 lane", 8192, 8, 1, true},
		{"1 pass, 8 lanes", 8192, 1, 8, true},
		{"9 passes: one over", 8192, 9, 1, false},
		{"9 lanes: one over", 8192, 1, 9, false},
		{"20 passes: the format maximum", 8192, 20, 1, false},
		{"255 lanes: the format maximum", 8192, 1, 255, false},
		{"1 GiB + 1 KiB: one over the memory ceiling", 1<<20 + 1, 1, 1, false},
		{"2 GiB", 1 << 21, 1, 1, false},
		{"4 GiB: the format maximum", 1 << 22, 1, 1, false},
	} {
		var hash string
		if tc.accept {
			hash = refHash(strong, tc.mem, tc.it, tc.par, salt)
		} else {
			// Refused hashes must not be derived at all: build the string
			// without computing the key (a 1 GiB derivation is seconds).
			hash = fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", tc.mem, tc.it, tc.par, enc(16), enc(32))
		}
		ok, err := m.Verify(strong, hash)
		switch {
		case tc.accept && (err != nil || !ok):
			t.Errorf("%s: Verify = %v, %v; want true, nil", tc.name, ok, err)
		case !tc.accept && (ok || !errors.Is(err, password.ErrInvalidHash)):
			t.Errorf("%s: Verify = %v, %v; want ErrInvalidHash", tc.name, ok, err)
		}
	}
}

// Raising the module's own cost raises the ceiling with it, to the edge and no
// further: a module at 2 passes accepts 16 and refuses 17.
func TestHostile_Ceiling_followsTheConfiguredCost(t *testing.T) {
	m := newModule(t, password.Config{Memory: 8 * 1024, Iterations: 2, Parallelism: 1})
	salt := []byte("0123456789abcdef")
	if ok, err := m.Verify(strong, refHash(strong, 8192, 16, 1, salt)); err != nil || !ok {
		t.Errorf("16 passes under a 2-pass module: %v, %v", ok, err)
	}
	over := "$argon2id$v=19$m=8192,t=17,p=1$" + enc(16) + "$" + enc(32)
	if ok, err := m.Verify(strong, over); ok || !errors.Is(err, password.ErrInvalidHash) {
		t.Errorf("17 passes under a 2-pass module: %v, %v; want ErrInvalidHash", ok, err)
	}
}
