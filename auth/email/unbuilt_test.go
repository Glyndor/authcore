package email_test

import (
	"context"
	"errors"
	"testing"

	"github.com/Glyndor/authcore/auth/email"
)

func TestEmail_unbuiltRefusesDomainLookups(t *testing.T) {
	var nilMod *email.Email
	for name, m := range map[string]*email.Email{"nil": nilMod, "zero": {}} {
		if err := m.VerifyDomain(context.Background(), "a@example.com"); !errors.Is(err, email.ErrInvalidConfig) {
			t.Errorf("%s VerifyDomain: %v", name, err)
		}
	}
	if _, err := nilMod.ValidateAndNormalize("a@example.com"); !errors.Is(err, email.ErrInvalidConfig) {
		t.Errorf("nil ValidateAndNormalize: %v", err)
	}
}
