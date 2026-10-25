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
