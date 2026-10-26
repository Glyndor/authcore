package claims

import (
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
