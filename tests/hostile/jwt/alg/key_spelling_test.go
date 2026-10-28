package alg

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/jwt"
	"github.com/Glyndor/authcore/tests/hostile/jwt/hostiletest"
)

// signParts signs an exact header and payload string with the module's key.
func signParts(e *hostiletest.Env, header, payload string) string {
	in := hostiletest.B64(header) + "." + hostiletest.B64(payload)
	return in + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(e.Priv, []byte(in)))
}

// A header or payload object has to be read one way only: a repeated key or a
// claim name spelt with another capitalisation is refused, whatever its order.
func TestHostile_ObjectKeysHaveOneReading(t *testing.T) {
	e := hostiletest.NewEnv(t)
	m := e.Module(t, jwt.Config{})
	cfg := jwt.DefaultConfig()
	now := time.Now().Unix()
	good := `"sub":"` + hostiletest.Subject + `","jti":"` + hostiletest.JtiA + `","iss":"` + cfg.Issuer + `","aud":"` + cfg.Audience[0] +
		`","iat":` + hostiletest.Itoa(now-1) + `,"exp":` + hostiletest.Itoa(now+600)
	head := `{"alg":"EdDSA","kid":"` + e.Kid + `","typ":"JWT"}`

	if _, err := m.VerifyAccessToken(signParts(e, head, `{`+good+`,"type":"access"}`)); err != nil {
		t.Fatalf("control token refused: %v", err)
	}

	payloads := map[string]string{
		"repeated key, first value valid": `{` + good + `,"type":"access","type":"refresh"}`,
		"repeated key, last value valid":  `{` + good + `,"type":"refresh","type":"access"}`,
		"repeated key with equal values":  `{` + good + `,"type":"access","type":"access"}`,
		"repeated key via escape":         `{` + good + `,"type":"access","type":"access"}`,
		"upper-case registered name":      strings.Replace(`{`+good+`,"type":"access"}`, `"exp"`, `"EXP"`, 1),
		"mixed-case type name":            `{` + good + `,"Type":"access"}`,
		"both capitalisations present":    `{` + good + `,"type":"access","TYPE":"access"}`,
		"custom names differing by case":  `{` + good + `,"type":"access","extra":{},"role":"a","Role":"b"}`,
	}
	for name, p := range payloads {
		t.Run("payload/"+name, func(t *testing.T) {
			_, err := m.VerifyAccessToken(signParts(e, head, p))
			if !hostiletest.IsInvalidOrMalformed(err) {
				t.Fatalf("token with ambiguous payload keys = %v, want ErrTokenInvalid or ErrTokenMalformed", err)
			}
		})
	}

	headers := map[string]string{
		"repeated kid":       `{"alg":"EdDSA","kid":"` + e.Kid + `","kid":"` + e.Kid + `","typ":"JWT"}`,
		"upper-case alg":     `{"ALG":"EdDSA","kid":"` + e.Kid + `","typ":"JWT"}`,
		"both kid spellings": `{"alg":"EdDSA","kid":"` + e.Kid + `","KID":"x","typ":"JWT"}`,
	}
	for name, h := range headers {
		t.Run("header/"+name, func(t *testing.T) {
			_, err := m.VerifyAccessToken(signParts(e, h, `{`+good+`,"type":"access"}`))
			if !hostiletest.IsInvalidOrMalformed(err) {
				t.Fatalf("token with ambiguous header keys = %v, want ErrTokenInvalid or ErrTokenMalformed", err)
			}
		})
	}
}
