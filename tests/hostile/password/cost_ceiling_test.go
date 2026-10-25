package password_test

import (
	"errors"
	"testing"

	"github.com/Glyndor/authcore/auth/password"
)

// A stored hash does not choose what a login costs: one asking for more than
// the module accepts is refused before any key is derived.
func TestHostile_Verify_costAboveTheCeilingIsRefused(t *testing.T) {
	m := newModule(t, lowCost())
	for name, params := range map[string]string{
		"memory":      "m=2097152,t=1,p=1",
		"iterations":  "m=8192,t=9,p=1",
		"parallelism": "m=8192,t=1,p=9",
		"parse limit": "m=4194304,t=20,p=255",
	} {
		hash := "$argon2id$v=19$" + params + "$" + enc(16) + "$" + enc(32)
		ok, err := m.Verify(strong, hash)
		if ok || !errors.Is(err, password.ErrInvalidHash) {
			t.Errorf("%s: Verify = %v, %v; want a refusal", name, ok, err)
		}
	}
}

// Each factor can sit under its own ceiling and the hash still be too costly:
// 1 GiB for 20 passes is about 13 s of one core. The product of memory and
// passes is refused before any key is derived, so these calls return at once.
func TestHostile_Verify_memoryTimesIterationsIsRefused(t *testing.T) {
	m := newModule(t, password.DefaultConfig())
	for name, params := range map[string]string{
		"1 GiB x 20":  "m=1048576,t=20,p=1",
		"1 GiB x 5":   "m=1048576,t=5,p=16",
		"512 MiB x 9": "m=524288,t=9,p=1",
	} {
		hash := "$argon2id$v=19$" + params + "$" + enc(16) + "$" + enc(32)
		ok, err := m.Verify(strong, hash)
		if ok || !errors.Is(err, password.ErrInvalidHash) {
			t.Errorf("%s: Verify = %v, %v; want a refusal", name, ok, err)
		}
	}
}
