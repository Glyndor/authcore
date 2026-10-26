package password_test

import (
	"errors"
	"testing"

	"github.com/Glyndor/authcore/auth/password"
)

func TestPassword_unbuiltRefusesEveryCall(t *testing.T) {
	var nilMod *password.Password
	for name, m := range map[string]*password.Password{"nil": nilMod, "zero": {}} {
		if _, err := m.Hash("Correct-Horse-9-Battery-Staple"); !errors.Is(err, password.ErrInvalidConfig) {
			t.Errorf("%s Hash: %v", name, err)
		}
		if ok, err := m.Verify("x", "y"); ok || !errors.Is(err, password.ErrInvalidConfig) {
			t.Errorf("%s Verify: %v, %v", name, ok, err)
		}
		if err := m.ValidatePolicy("x"); !errors.Is(err, password.ErrInvalidConfig) {
			t.Errorf("%s ValidatePolicy: %v", name, err)
		}
	}
}
