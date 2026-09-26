package totp

import (
	"context"
	"errors"
	"testing"
)

// A TOTP that New did not build has no pepper. Every method refuses on it
// (2026-09-25); before, HashRecoveryCode hashed under an empty key and
// VerifyRecoveryCode compared against such hashes.
func TestZeroValueTOTP_refusesEveryMethod(t *testing.T) {
	for name, mod := range map[string]*TOTP{"zero value": {}, "nil pointer": nil} {
		t.Run(name, func(t *testing.T) {
			if _, err := mod.Enroll("alice@example.com"); !errors.Is(err, ErrNotInitialised) {
				t.Errorf("Enroll = %v", err)
			}
			if _, err := mod.VerifyStep("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP", "123456", 0); !errors.Is(err, ErrNotInitialised) {
				t.Errorf("VerifyStep = %v", err)
			}
			if err := mod.Verify(context.Background(), "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP", "123456", &memoryRecorder{}); !errors.Is(err, ErrNotInitialised) {
				t.Errorf("Verify = %v", err)
			}
			if h, err := mod.HashRecoveryCode("ABCD1234-EFGH5678"); !errors.Is(err, ErrNotInitialised) || h != "" {
				t.Errorf("HashRecoveryCode = %q, %v", h, err)
			}
			// The hash anyone can compute under an empty key must not match.
			empty := (&TOTP{}).hashRecoveryCode("ABCD1234EFGH5678")
			if _, ok := mod.VerifyRecoveryCode("ABCD1234-EFGH5678", []string{empty}); ok {
				t.Error("VerifyRecoveryCode accepted a hash keyed with nothing")
			}
		})
	}
	// The built module still does all of it.
	mod := newTOTP(t)
	enr, err := mod.Enroll("alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if h, err := mod.HashRecoveryCode(enr.RecoveryCodes[0]); err != nil || h != enr.RecoveryHashes[0] {
		t.Fatalf("HashRecoveryCode on the built module = %q, %v", h, err)
	}
}
