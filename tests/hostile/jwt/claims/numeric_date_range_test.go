package claims

import (
	"errors"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/jwt"
	"github.com/Glyndor/authcore/tests/hostile/jwt/hostiletest"
)

// A time claim too large for time.Time is refused: it must not be read as a
// date in the past, which would skip the "issued in the future" and "not valid
// yet" checks.
func TestHostile_Time_oversizedIatAndNbfAreRefused(t *testing.T) {
	e := hostiletest.NewEnv(t)
	m := e.Module(t, jwt.Config{})
	for _, claim := range []string{"iat", "nbf"} {
		now := time.Now().Unix()
		iat, nbf := hostiletest.Itoa(now-1), ""
		if claim == "iat" {
			iat = "9223372036854775807"
		} else {
			nbf = `"nbf":9223372036854775807,`
		}
		payload := `{"iss":"` + jwt.DefaultConfig().Issuer + `","aud":"` + jwt.DefaultConfig().Audience[0] + `","sub":"` + hostiletest.Subject +
			`","jti":"` + hostiletest.JtiA + `",` + nbf + `"iat":` + iat + `,"exp":` + hostiletest.Itoa(now+600) + `,"type":"access"}`
		if c, err := m.VerifyAccessToken(e.SignRaw(t, payload)); err == nil {
			t.Errorf("%s=int64 max was accepted: %+v", claim, c)
		}
	}
}

// A date outside 1970..9999 is refused on both token kinds, whichever of the
// three time claims carries it: the signature being valid is not enough.
func TestHostile_Time_datesOutsideTheSupportedRangeAreRefusedOnBothKinds(t *testing.T) {
	e := hostiletest.NewEnv(t)
	m := e.Module(t, jwt.Config{})
	bad := map[string]map[string]any{
		"iat before 1970": {"iat": int64(-1)},
		"nbf before 1970": {"nbf": int64(-5)},
		"exp after 9999":  {"exp": int64(253402300800)},
	}
	for name, override := range bad {
		for _, typ := range []string{"access", "refresh"} {
			c := hostiletest.ClaimsFor(typ)
			for k, v := range override {
				c = hostiletest.With(c, k, v)
			}
			token := e.SignEdDSA(t, nil, c)
			var err error
			if typ == "access" {
				_, err = m.VerifyAccessToken(token)
			} else {
				_, err = m.RotateTokens(token, hostiletest.Extra{})
			}
			if !errors.Is(err, jwt.ErrTokenInvalid) {
				t.Errorf("%s on a %s token: %v, want ErrTokenInvalid", name, typ, err)
			}
		}
	}
	// Control: the same shapes with in-range dates are accepted.
	if _, err := m.RotateTokens(e.SignEdDSA(t, nil, hostiletest.ClaimsFor("refresh")), hostiletest.Extra{}); err != nil {
		t.Fatalf("control refresh token refused: %v", err)
	}
}
