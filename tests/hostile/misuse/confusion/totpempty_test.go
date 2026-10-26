package confusion

import (
	"errors"
	"testing"

	"github.com/Glyndor/authcore/auth/totp"
	"github.com/Glyndor/authcore/tests/hostile/misuse/hostiletest"
)

// An empty account name or an empty recovery code is not a value to enrol or
// to redeem.
func TestMisuse_Confusion_totpRefusesEmptyInputs(t *testing.T) {
	e := hostiletest.NewEnv(t)
	m, err := totp.New(e.AC)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"", " ", "\t\n"} {
		if _, err := m.Enroll(name); !errors.Is(err, totp.ErrInvalidConfig) {
			t.Errorf("Enroll(%q): got %v, want ErrInvalidConfig", name, err)
		}
	}
	for _, code := range []string{"", " ", "-", " - - "} {
		h, err := m.HashRecoveryCode(code)
		if err != nil {
			t.Fatal(err)
		}
		if i, ok := m.VerifyRecoveryCode(code, []string{h}); ok {
			t.Errorf("VerifyRecoveryCode(%q) matched its own hash at %d", code, i)
		}
	}
	enr, err := m.Enroll("ana")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := m.VerifyRecoveryCode(enr.RecoveryCodes[0], enr.RecoveryHashes); !ok {
		t.Error("a real recovery code stopped verifying")
	}
}
