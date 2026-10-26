package apikey_test

import (
	"errors"
	"testing"

	"github.com/Glyndor/authcore/auth/apikey"
)

func TestAPIKey_nilReceiverRefusesEveryCall(t *testing.T) {
	var m *apikey.APIKey
	if _, err := m.Generate(); !errors.Is(err, apikey.ErrNotInitialised) {
		t.Errorf("Generate: %v", err)
	}
	if _, err := m.Hash("k"); !errors.Is(err, apikey.ErrNotInitialised) {
		t.Errorf("Hash: %v", err)
	}
	if m.Verify("k", "h") {
		t.Error("Verify accepted a key")
	}
}
