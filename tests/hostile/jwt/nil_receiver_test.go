package jwt_test

import (
	"errors"
	"testing"

	"github.com/Glyndor/authcore/auth/jwt"
)

// A nil *JWT answers like a zero value does: an error or false, never a panic.
func TestHostile_Module_nilReceiverRefreshHash(t *testing.T) {
	var m *jwt.JWT[extra]
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("a nil *JWT panicked: %v", r)
		}
	}()
	if m.VerifyRefreshTokenHash("t", "h") {
		t.Error("a nil module verified a hash")
	}
	if h, err := m.HashRefreshToken("t"); h != "" || !errors.Is(err, jwt.ErrNotInitialised) {
		t.Errorf("HashRefreshToken on nil = %q, %v; want ErrNotInitialised", h, err)
	}
}
