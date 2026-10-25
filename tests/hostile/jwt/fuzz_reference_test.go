package jwt_test

import (
	"bytes"
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/jwt"
)

// canonicalClaims reports whether payload is a JSON object with the one
// spelling every implementation reads the same way: no repeated key, only the
// exact lower-case claim names, and the three dates as JSON numbers. The module
// is deliberately more lenient than that in three places (the last of a
// repeated key wins, encoding/json matches field names case-insensitively, a
// quoted number is a date), none of which an attacker without the signing key
// can reach; outside them, the two verifiers must agree.
func canonicalClaims(payload []byte) bool {
	d := json.NewDecoder(bytes.NewReader(payload))
	if tok, err := d.Token(); err != nil || tok != json.Delim('{') {
		return false
	}
	seen := map[string]bool{}
	for d.More() {
		k, err := d.Token()
		key, ok := k.(string)
		if err != nil || !ok || seen[key] || key != strings.ToLower(key) {
			return false
		}
		seen[key] = true
		var v json.RawMessage
		if err := d.Decode(&v); err != nil {
			return false
		}
		if (key == "exp" || key == "iat" || key == "nbf") && len(v) > 0 && v[0] == '"' {
			return false
		}
	}
	_, err := d.Token() // closing brace
	if err != nil {
		return false
	}
	_, err = d.Token()
	return err == io.EOF
}

// FuzzVerifyAccessTokenAgreesWithReference signs arbitrary claim payloads with
// the module's real key and requires that anything the module accepts, the
// independent verifier accepts too. The other direction is not asserted: the
// module also checks things the reference does not model.
func FuzzVerifyAccessTokenAgreesWithReference(f *testing.F) {
	e := newEnv(f)
	m := e.module(f, jwt.Config{})
	now := time.Now().Unix()
	base := `{"iss":"github.com/Glyndor/authcore","aud":"github.com/Glyndor/authcore","sub":"` + subject + `","jti":"` + jtiA +
		`","iat":` + strconv.FormatInt(now-5, 10) + `,"exp":` + strconv.FormatInt(now+3600, 10) + `,"type":"access"}`
	f.Add(base)
	f.Add(strings.Replace(base, `"aud":"github.com/Glyndor/authcore"`, `"aud":["x","github.com/Glyndor/authcore"]`, 1))
	f.Add(strings.Replace(base, `"type":"access"`, `"type":"access","extra":{"role":"admin"}`, 1))
	f.Add(strings.Replace(base, `"iat"`, `"nbf":1,"iat"`, 1))
	f.Add(strings.Replace(base, `"sub":"`+subject+`"`, `"sub":"0191B432-B5A7-7C4F-B2E6-7A3F1D2E0001"`, 1))
	f.Add(strings.Replace(base, `"aud":"github.com/Glyndor/authcore"`, `"aud":[]`, 1))
	f.Add(strings.Replace(base, strconv.FormatInt(now+3600, 10), "1e10", 1))
	// Payloads the module refuses; they matter when a check is removed.
	f.Add(strings.Replace(base, `"iss":"github.com/Glyndor/authcore"`, `"iss":"elsewhere"`, 1))
	f.Add(strings.Replace(base, `"aud":"github.com/Glyndor/authcore"`, `"aud":"elsewhere"`, 1))
	f.Add(strings.Replace(base, `"type":"access"`, `"type":"refresh"`, 1))
	f.Add(strings.Replace(base, `7c4f`, `4c4f`, 1))
	f.Add(strings.Replace(base, strconv.FormatInt(now+3600, 10), strconv.FormatInt(now-3600, 10), 1))
	f.Add(strings.Replace(base, strconv.FormatInt(now-5, 10), strconv.FormatInt(now+3600, 10), 1))

	f.Fuzz(func(t *testing.T, payload string) {
		if !canonicalClaims([]byte(payload)) {
			return
		}
		token := e.signRaw(t, payload)
		if _, err := m.VerifyAccessToken(token); err != nil {
			return
		}
		p := e.policy("access")
		p.now = time.Now()
		if err := refVerify(token, p); err != nil {
			// Skip the instants where the second turned over between the two checks.
			var c map[string]json.Number
			_ = json.Unmarshal([]byte(payload), &c)
			for _, k := range []string{"exp", "iat", "nbf"} {
				if v, err := c[k].Float64(); err == nil && v > float64(p.now.Unix()-3) && v < float64(p.now.Unix()+3) {
					return
				}
			}
			t.Fatalf("the module accepted a canonical payload the independent verifier refuses (%v): %s", err, payload)
		}
	})
}
