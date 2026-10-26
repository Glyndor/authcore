package username_test

import (
	"errors"
	"testing"

	"github.com/Glyndor/authcore/auth/username"
)

func TestUsername_nilAcceptsNothing(t *testing.T) {
	var m *username.Username
	if _, err := m.ValidateAndNormalize("bob"); !errors.Is(err, username.ErrInvalidUsername) {
		t.Errorf("nil ValidateAndNormalize: %v", err)
	}
}
