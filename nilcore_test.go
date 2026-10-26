package authcore_test

import (
	"testing"

	"github.com/Glyndor/authcore"
)

func TestNilCore_accessorsAnswerEmpty(t *testing.T) {
	var ac *authcore.AuthCore
	if ac.Logger() != nil {
		t.Error("Logger() on a nil core returned a logger")
	}
	if ac.Keys() != nil {
		t.Error("Keys() on a nil core returned keys")
	}
	if got := ac.Config(); got.KeysDir != "" || got.EnableLogs {
		t.Errorf("Config() on a nil core returned %+v", got)
	}
}
