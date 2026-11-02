package keys

import (
	"errors"
	"testing"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/jwt"
	"github.com/Glyndor/authcore/tests/hostile/jwt/hostiletest"
)

// emptyKeyID is a Provider whose key set answers an empty key id, which the
// Keys contract forbids and authcore.New refuses; jwt.New receives any Provider.
type emptyKeyID struct{ authcore.Keys }

func (emptyKeyID) KeyID() string { return "" }

type emptyKeyIDProvider struct{ authcore.Provider }

func (p emptyKeyIDProvider) Keys() authcore.Keys { return emptyKeyID{p.Provider.Keys()} }

// Guards the empty-id check in auth/jwt/jwt.go New. A module registered under
// the id "" would verify a token whose header has no kid at all, because an
// absent kid reads as "": the verification would no longer select the key by
// the id the token names.
func TestHostile_JWT_aProviderWithAnEmptyKeyIDIsRefused(t *testing.T) {
	e := hostiletest.NewEnv(t)
	m, err := jwt.New[hostiletest.Extra](emptyKeyIDProvider{e.Prov}, jwt.Config{})
	if err == nil {
		tok := e.SignEdDSA(t, map[string]any{"kid": nil}, hostiletest.ClaimsFor("access"))
		if _, verr := m.VerifyAccessToken(tok); verr == nil {
			t.Fatal("a token with no kid header verified under an empty key id")
		}
		t.Fatal("jwt.New accepted a provider whose key id is empty")
	}
	if !errors.Is(err, jwt.ErrInvalidConfig) {
		t.Fatalf("err = %v, want ErrInvalidConfig", err)
	}
}
