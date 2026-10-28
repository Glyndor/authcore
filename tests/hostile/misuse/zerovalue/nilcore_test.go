package zerovalue

import (
	"errors"
	"testing"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/tests/hostile/misuse/hostiletest"
)

// A nil *AuthCore is what `ac, _ := authcore.New(cfg)` leaves behind when the
// error is dropped. Every constructor must answer with its own
// ErrInvalidConfig and none may panic.
func TestMisuse_ZeroValue_constructorsRefuseANilCore(t *testing.T) {
	var ac *authcore.AuthCore
	for _, c := range constructors() {
		t.Run(c.name, func(t *testing.T) {
			var err error
			hostiletest.NoPanic(t, c.name+".New", func() { err = c.new(ac) })
			if !errors.Is(err, c.sent) {
				t.Fatalf("got %v, want %v", err, c.sent)
			}
		})
	}
}

// The accessors of a nil core answer with the zero value rather than panic.
func TestMisuse_ZeroValue_nilCoreAccessorsAnswerEmpty(t *testing.T) {
	var ac *authcore.AuthCore
	hostiletest.NoPanic(t, "accessors", func() {
		if ac.Logger() != nil {
			t.Error("Logger() on a nil core returned a logger")
		}
		if ac.Keys() != nil {
			t.Error("Keys() on a nil core returned keys")
		}
		if got := ac.Config(); got.KeysDir != "" {
			t.Errorf("Config() on a nil core returned %+v", got)
		}
	})
}
