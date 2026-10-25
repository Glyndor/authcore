package jwt_test

import (
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/jwt"
)

// A time claim too large for time.Time is refused: it must not be read as a
// date in the past, which would skip the "issued in the future" and "not valid
// yet" checks.
func TestHostile_Time_oversizedIatAndNbfAreRefused(t *testing.T) {
	e := newEnv(t)
	m := e.module(t, jwt.Config{})
	for _, claim := range []string{"iat", "nbf"} {
		now := time.Now().Unix()
		iat, nbf := itoa(now-1), ""
		if claim == "iat" {
			iat = "9223372036854775807"
		} else {
			nbf = `"nbf":9223372036854775807,`
		}
		payload := `{"iss":"` + jwt.DefaultConfig().Issuer + `","aud":"` + jwt.DefaultConfig().Audience[0] + `","sub":"` + subject +
			`","jti":"` + jtiA + `",` + nbf + `"iat":` + iat + `,"exp":` + itoa(now+600) + `,"type":"access"}`
		if c, err := m.VerifyAccessToken(e.signRaw(t, payload)); err == nil {
			t.Errorf("%s=int64 max was accepted: %+v", claim, c)
		}
	}
}
