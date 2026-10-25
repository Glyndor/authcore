package parse_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/jwt/internal/claims"
	"github.com/Glyndor/authcore/auth/jwt/internal/jwterr"
	"github.com/Glyndor/authcore/auth/jwt/internal/jwttest"
	"github.com/Glyndor/authcore/auth/jwt/internal/parse"
)

const goodJTI = "019600ab-0000-7000-8000-000000000042"

// A token whose signature, issuer, audience, expiry and type all check out
// still has to carry a UUID v7 sub and jti: the parse refuses it on the
// claim that fails and says which one.
func TestAccess_refusesAMalformedSubjectOrSessionID(t *testing.T) {
	j := newRig[struct{}](t, jwttest.DefaultConfig())
	for name, tc := range map[string]struct{ sub, jti, claim string }{
		"empty subject": {"", goodJTI, "sub"},
		"empty jti":     {jwttest.Subject, "", "jti"},
		"not a uuid":    {"not-a-uuid", goodJTI, "sub"},
	} {
		t.Run(name, func(t *testing.T) {
			cl := claims.NewAccess(j.Cfg.Issuer, tc.sub, tc.jti, j.Cfg.Audience, struct{}{}, jwttest.Epoch, time.Minute)
			tok := jwttest.SignAccess(t, cl, j.K.Priv, j.K.KeyID())

			_, err := parse.Access[struct{}](tok, j.Keys, jwttest.Epoch, j.Cfg.Issuer, j.Cfg.Audience[0], 0)
			if !errors.Is(err, jwterr.ErrTokenInvalid) || !strings.Contains(err.Error(), tc.claim) {
				t.Fatalf("Access = %v, want ErrTokenInvalid naming %s", err, tc.claim)
			}
		})
	}

	good := jwttest.SignAccess(t, claims.NewAccess(j.Cfg.Issuer, jwttest.Subject, goodJTI, j.Cfg.Audience, struct{}{}, jwttest.Epoch, time.Minute), j.K.Priv, j.K.KeyID())
	if c, err := parse.Access[struct{}](good, j.Keys, jwttest.Epoch, j.Cfg.Issuer, j.Cfg.Audience[0], 0); err != nil || c.ID != goodJTI {
		t.Fatalf("Access on well-formed identifiers = %+v, %v; want accepted", c, err)
	}
}

func TestRefresh_refusesAMalformedSubjectOrSessionID(t *testing.T) {
	j := newRig[struct{}](t, jwttest.DefaultConfig())
	for name, tc := range map[string]struct{ sub, jti, claim string }{
		"bad subject": {"not-a-uuid", goodJTI, "sub"},
		"bad jti":     {jwttest.Subject, "not-a-uuid", "jti"},
	} {
		t.Run(name, func(t *testing.T) {
			cl := claims.NewRefresh(j.Cfg.Issuer, tc.sub, tc.jti, "", j.Cfg.Audience, jwttest.Epoch, time.Hour)
			tok := jwttest.SignRefresh(t, cl, j.K.Priv, j.K.KeyID())

			_, err := parse.Refresh(tok, j.Keys, jwttest.Epoch, j.Cfg.Issuer, j.Cfg.Audience[0], 0)
			if !errors.Is(err, jwterr.ErrTokenInvalid) || !strings.Contains(err.Error(), tc.claim) {
				t.Fatalf("Refresh = %v, want ErrTokenInvalid naming %s", err, tc.claim)
			}
		})
	}

	good := jwttest.SignRefresh(t, claims.NewRefresh(j.Cfg.Issuer, jwttest.Subject, goodJTI, "", j.Cfg.Audience, jwttest.Epoch, time.Hour), j.K.Priv, j.K.KeyID())
	if c, err := parse.Refresh(good, j.Keys, jwttest.Epoch, j.Cfg.Issuer, j.Cfg.Audience[0], 0); err != nil || c.ID != goodJTI {
		t.Fatalf("Refresh on well-formed identifiers = %+v, %v; want accepted", c, err)
	}
}
