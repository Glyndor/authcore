package denylist

import (
	"context"
	"errors"
	"testing"

	"github.com/Glyndor/authcore/auth/jwt"
	"github.com/Glyndor/authcore/tests/hostile/jwt/hostiletest"
)

// valueDenylist is a store held by value, not behind a pointer.
type valueDenylist struct{ revoked string }

func (d valueDenylist) IsRevoked(_ context.Context, jti string) (bool, error) {
	return jti == d.revoked, nil
}

// A denylist that is not a pointer, map, slice, func or channel is a real
// store, not a nil one: it is accepted and consulted.
func TestHostile_Denylist_storeHeldByValueIsConsulted(t *testing.T) {
	e := hostiletest.NewEnv(t)
	live, err := e.Module(t, jwt.Config{}).CreateTokens(hostiletest.Subject, hostiletest.Extra{})
	if err != nil {
		t.Fatal(err)
	}
	live2, err := e.Module(t, jwt.Config{}).CreateTokens(hostiletest.Subject, hostiletest.Extra{})
	if err != nil {
		t.Fatal(err)
	}
	m := e.Module(t, jwt.Config{Denylist: valueDenylist{revoked: live.SessionID}})
	if _, err := m.VerifyAccessToken(live.AccessToken); !errors.Is(err, jwt.ErrTokenRevoked) {
		t.Fatalf("a session the value-typed store revoked = %v, want ErrTokenRevoked", err)
	}
	if _, err := m.VerifyAccessToken(live2.AccessToken); err != nil {
		t.Fatalf("a session the store did not revoke was refused: %v", err)
	}
}
