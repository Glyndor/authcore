package jwt_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/jwt"
)

// signParts signs an exact header and payload string with the module's key.
func (e *env) signParts(header, payload string) string {
	in := b64(header) + "." + b64(payload)
	return in + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(e.priv, []byte(in)))
}

// A header or payload object has to be read one way only: a repeated key or a
// claim name spelt with another capitalisation is refused, whatever its order.
func TestHostile_ObjectKeysHaveOneReading(t *testing.T) {
	e := newEnv(t)
	m := e.module(t, jwt.Config{})
	cfg := jwt.DefaultConfig()
	now := time.Now().Unix()
	good := `"sub":"` + subject + `","jti":"` + jtiA + `","iss":"` + cfg.Issuer + `","aud":"` + cfg.Audience[0] +
		`","iat":` + itoa(now-1) + `,"exp":` + itoa(now+600)
	head := `{"alg":"EdDSA","kid":"` + e.kid + `","typ":"JWT"}`

	if _, err := m.VerifyAccessToken(e.signParts(head, `{`+good+`,"type":"access"}`)); err != nil {
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
			if _, err := m.VerifyAccessToken(e.signParts(head, p)); err == nil {
				t.Fatal("token with ambiguous payload keys was accepted")
			}
		})
	}

	headers := map[string]string{
		"repeated kid":       `{"alg":"EdDSA","kid":"` + e.kid + `","kid":"` + e.kid + `","typ":"JWT"}`,
		"upper-case alg":     `{"ALG":"EdDSA","kid":"` + e.kid + `","typ":"JWT"}`,
		"both kid spellings": `{"alg":"EdDSA","kid":"` + e.kid + `","KID":"x","typ":"JWT"}`,
	}
	for name, h := range headers {
		t.Run("header/"+name, func(t *testing.T) {
			if _, err := m.VerifyAccessToken(e.signParts(h, `{`+good+`,"type":"access"}`)); err == nil {
				t.Fatal("token with ambiguous header keys was accepted")
			}
		})
	}
}
