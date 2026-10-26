package claims

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/jwt"
	"github.com/Glyndor/authcore/tests/hostile/jwt/hostiletest"
)

func payloadOf(t *testing.T, token string) map[string]any {
	t.Helper()
	seg := strings.Split(token, ".")
	if len(seg) != 3 {
		t.Fatalf("token has %d segments", len(seg))
	}
	raw, err := base64.RawURLEncoding.DecodeString(seg[1])
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// The lifetimes a caller gets without configuring anything are 15 minutes and
// 24 hours, in the policy and in the tokens signed under it.
func TestHostile_Claims_defaultLifetimesAreFifteenMinutesAndOneDay(t *testing.T) {
	cfg := jwt.DefaultConfig()
	if cfg.AccessTokenTTL != 15*time.Minute || cfg.RefreshTokenTTL != 24*time.Hour {
		t.Fatalf("DefaultConfig TTLs = %s and %s, want 15m and 24h", cfg.AccessTokenTTL, cfg.RefreshTokenTTL)
	}
	e := hostiletest.NewEnv(t)
	pair, err := e.Module(t, jwt.Config{}).CreateTokens(hostiletest.Subject, hostiletest.Extra{})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name  string
		token string
		want  float64
	}{
		{"access", pair.AccessToken, 15 * 60},
		{"refresh", pair.RefreshToken, 24 * 60 * 60},
	} {
		p := payloadOf(t, c.token)
		if got := p["exp"].(float64) - p["iat"].(float64); got != c.want {
			t.Errorf("%s token lives %v seconds, want %v", c.name, got, c.want)
		}
	}
}
