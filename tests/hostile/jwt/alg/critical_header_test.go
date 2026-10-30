package alg

import (
	"errors"
	"testing"

	"github.com/Glyndor/authcore/auth/jwt"
	"github.com/Glyndor/authcore/tests/hostile/jwt/hostiletest"
)

// Sign with the trusted key so a bad signature cannot mask an ignored crit.
func TestHostile_TrustedJWTWithUnknownCritIsRefused(t *testing.T) {
	e := hostiletest.NewEnv(t)
	m := e.Module(t, jwt.Config{})
	for _, kind := range []string{"access", "refresh"} {
		t.Run(kind, func(t *testing.T) {
			claims := hostiletest.ClaimsFor(kind)
			verify := func(token string) (bool, error) {
				if kind == "access" {
					got, err := m.VerifyAccessToken(token)
					return got != nil, err
				}
				got, err := m.RotateTokens(token, hostiletest.Extra{})
				return got != nil, err
			}
			for _, header := range []map[string]any{nil, {"policy": "deny"}} {
				if got, err := verify(e.SignEdDSA(t, header, claims)); !got || err != nil {
					t.Fatalf("control without crit = %v, %v; want result and nil", got, err)
				}
			}
			for name, crit := range map[string]any{
				"unknown policy": []string{"policy"},
				"multiple":       []string{"policy", "other"},
				"registered kid": []string{"kid"},
				"empty list":     []string{},
				"string":         "policy",
				"number":         1,
				"object":         map[string]any{"policy": true},
			} {
				t.Run(name, func(t *testing.T) {
					header := map[string]any{"crit": crit, "policy": "deny", "other": true}
					got, err := verify(e.SignEdDSA(t, header, claims))
					if got || !errors.Is(err, jwt.ErrTokenInvalid) {
						t.Fatalf("trusted token with crit = %v, %v; want no result and ErrTokenInvalid", got, err)
					}
				})
			}
		})
	}
}
