// Package claims attacks the JWT claims: wrong shapes, extreme numbers,
// time bounds and numeric date ranges.
package claims

import (
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/jwt"
	"github.com/Glyndor/authcore/tests/hostile/jwt/hostiletest"
)

// Every registered claim is checked against the shape the module issues. A
// signed token whose claim has the wrong JSON type is refused, never coerced
// into something that passes.
func TestHostile_ClaimTypes_wrongShapesAreRefused(t *testing.T) {
	e := hostiletest.NewEnv(t)
	m := e.Module(t, jwt.Config{})

	if _, err := m.VerifyAccessToken(e.SignEdDSA(t, nil, hostiletest.ClaimsFor("access"))); err != nil {
		t.Fatalf("control token refused: %v", err)
	}

	cases := map[string]struct {
		key  string
		v    any
		want error
	}{
		"exp object":           {"exp", map[string]any{"$date": 9999999999}, jwt.ErrTokenMalformed},
		"exp array":            {"exp", []any{9999999999}, jwt.ErrTokenMalformed},
		"exp bool":             {"exp", true, jwt.ErrTokenMalformed},
		"exp null":             {"exp", nil, jwt.ErrTokenInvalid},
		"iat object":           {"iat", map[string]any{}, jwt.ErrTokenMalformed},
		"aud object":           {"aud", map[string]any{"a": jwt.DefaultConfig().Audience[0]}, jwt.ErrTokenMalformed},
		"aud number":           {"aud", 7, jwt.ErrTokenMalformed},
		"aud empty string":     {"aud", "", jwt.ErrTokenInvalid},
		"aud empty array":      {"aud", []any{}, jwt.ErrTokenInvalid},
		"aud array of numbers": {"aud", []any{1, 2}, jwt.ErrTokenMalformed},
		"aud other service":    {"aud", "https://other.example", jwt.ErrTokenInvalid},
		"aud near miss":        {"aud", jwt.DefaultConfig().Audience[0] + " ", jwt.ErrTokenInvalid},
		"aud nested array":     {"aud", []any{[]any{jwt.DefaultConfig().Audience[0]}}, jwt.ErrTokenMalformed},
		"aud missing":          {"aud", nil, jwt.ErrTokenInvalid},
		"iss array":            {"iss", []any{jwt.DefaultConfig().Issuer}, jwt.ErrTokenMalformed},
		"iss number":           {"iss", 1, jwt.ErrTokenMalformed},
		"iss other issuer":     {"iss", "https://attacker.example", jwt.ErrTokenInvalid},
		"iss near miss":        {"iss", jwt.DefaultConfig().Issuer + "/", jwt.ErrTokenInvalid},
		"iss missing":          {"iss", nil, jwt.ErrTokenInvalid},
		"sub number":           {"sub", 12345, jwt.ErrTokenMalformed},
		"sub array":            {"sub", []any{hostiletest.Subject}, jwt.ErrTokenMalformed},
		"sub missing":          {"sub", nil, jwt.ErrTokenInvalid},
		"sub not a uuid":       {"sub", "admin", jwt.ErrTokenInvalid},
		"sub uuid v4":          {"sub", "0191b432-b5a7-4c4f-b2e6-7a3f1d2e0001", jwt.ErrTokenInvalid},
		"sub trailing newline": {"sub", hostiletest.Subject + "\n", jwt.ErrTokenInvalid},
		"sub with NUL":         {"sub", hostiletest.Subject[:35] + "\x00", jwt.ErrTokenInvalid},
		"sub uuid in braces":   {"sub", "{" + hostiletest.Subject + "}", jwt.ErrTokenInvalid},
		"sub urn form":         {"sub", "urn:uuid:" + hostiletest.Subject, jwt.ErrTokenInvalid},
		"sub bad variant":      {"sub", "0191b432-b5a7-7c4f-c2e6-7a3f1d2e0001", jwt.ErrTokenInvalid},
		"jti number":           {"jti", 1, jwt.ErrTokenMalformed},
		"jti object":           {"jti", map[string]any{}, jwt.ErrTokenMalformed},
		"jti missing":          {"jti", nil, jwt.ErrTokenInvalid},
		"jti not a uuid":       {"jti", "session-1", jwt.ErrTokenInvalid},
		"jti uppercase v4":     {"jti", "0191B432-B5A7-4C4F-B2E6-7A3F1D2E0002", jwt.ErrTokenInvalid},
		"jti unicode digits":   {"jti", "0191b432-b5a7-7c4f-b2e6-7a3f1d2e000\u0661", jwt.ErrTokenInvalid},
		"type object":          {"type", map[string]any{}, jwt.ErrTokenMalformed},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			token := e.SignEdDSA(t, nil, hostiletest.With(hostiletest.ClaimsFor("access"), tc.key, tc.v))
			c, err := m.VerifyAccessToken(token)
			if c != nil || !errors.Is(err, tc.want) {
				t.Fatalf("%s=%v: got %+v, %v; want no claims and %v", tc.key, tc.v, c, err, tc.want)
			}
		})
	}
}

// golang-jwt reads a numeric date written as a JSON string ("exp":"123") as the
// number 123. That leniency is harmless only while the value is honoured at
// face value: a string date that is in the past or the future must act like the
// number would, never be dropped as if the claim were absent.
func TestHostile_ClaimTypes_stringDatesAreHonouredNotIgnored(t *testing.T) {
	e := hostiletest.NewEnv(t)
	m := e.Module(t, jwt.Config{})
	now := time.Now()
	cases := map[string]struct {
		key  string
		v    string
		want error
	}{
		"exp string in the past": {"exp", "1", jwt.ErrTokenExpired},
		"iat string in future":   {"iat", strconv.FormatInt(now.Add(time.Hour).Unix(), 10), jwt.ErrTokenInvalid},
		"nbf string in future":   {"nbf", strconv.FormatInt(now.Add(time.Hour).Unix(), 10), jwt.ErrTokenInvalid},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			token := e.SignEdDSA(t, nil, hostiletest.With(hostiletest.ClaimsFor("access"), tc.key, tc.v))
			if c, err := m.VerifyAccessToken(token); c != nil || !errors.Is(err, tc.want) {
				t.Fatalf("VerifyAccessToken = %+v, %v; want %v", c, err, tc.want)
			}
		})
	}
}

// The audience claim may legitimately be an array. The module is one of the
// audiences it names, and one match is enough; a list that does not name it
// is not.
func TestHostile_ClaimTypes_audienceArrayNeedsOurAudience(t *testing.T) {
	e := hostiletest.NewEnv(t)
	m := e.Module(t, jwt.Config{Audience: []string{"https://api.example", "https://other.example"}})
	cfgAud := "https://api.example"

	accept := []any{cfgAud, []any{cfgAud}, []any{"https://elsewhere.example", cfgAud}}
	for i, aud := range accept {
		token := e.SignEdDSA(t, nil, hostiletest.With(hostiletest.ClaimsFor("access"), "aud", aud))
		if _, err := m.VerifyAccessToken(token); err != nil {
			t.Errorf("accept case %d (%v): %v", i, aud, err)
		}
	}

	// Only Audience[0] is the audience this module checks: a token for the
	// second configured audience alone is refused.
	token := e.SignEdDSA(t, nil, hostiletest.With(hostiletest.ClaimsFor("access"), "aud", "https://other.example"))
	if c, err := m.VerifyAccessToken(token); c != nil || !errors.Is(err, jwt.ErrTokenInvalid) {
		t.Fatalf("a token for the secondary audience only: got %+v, %v; want no claims and ErrTokenInvalid", c, err)
	}
}

// The extra payload has a fixed shape. A signed token whose extra holds the
// wrong JSON type is refused instead of yielding a half-filled struct.
func TestHostile_ClaimTypes_extraWithWrongShape(t *testing.T) {
	e := hostiletest.NewEnv(t)
	m := e.Module(t, jwt.Config{})

	if c, err := m.VerifyAccessToken(e.SignEdDSA(t, nil, hostiletest.With(hostiletest.ClaimsFor("access"), "extra", map[string]any{"role": "admin"}))); err != nil || c.Extra.Role != "admin" {
		t.Fatalf("control: %+v, %v", c, err)
	}
	for name, ex := range map[string]any{
		"role number":  map[string]any{"role": 5},
		"role array":   map[string]any{"role": []any{"admin"}},
		"role object":  map[string]any{"role": map[string]any{"a": 1}},
		"extra array":  []any{"admin"},
		"extra string": "admin",
		"extra number": 1,
	} {
		t.Run(name, func(t *testing.T) {
			token := e.SignEdDSA(t, nil, hostiletest.With(hostiletest.ClaimsFor("access"), "extra", ex))
			if c, err := m.VerifyAccessToken(token); c != nil || !errors.Is(err, jwt.ErrTokenMalformed) {
				t.Fatalf("extra=%v: got %+v, %v; want no claims and ErrTokenMalformed", ex, c, err)
			}
		})
	}
}

// Extra cannot reach the registered claims: a field that carries the name of
// a registered claim inside "extra" stays inside it.
func TestHostile_ClaimTypes_extraCannotOverrideRegisteredClaims(t *testing.T) {
	e := hostiletest.NewEnv(t)
	type loud struct {
		Sub  string `json:"sub"`
		Exp  int64  `json:"exp"`
		Type string `json:"type"`
	}
	m, err := jwt.New[loud](e.Prov)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := m.CreateTokens(hostiletest.Subject, loud{Sub: "attacker", Exp: 1, Type: "refresh"})
	if err != nil {
		t.Fatal(err)
	}
	c, err := m.VerifyAccessToken(pair.AccessToken)
	if err != nil {
		t.Fatalf("a payload named like registered claims broke a valid token: %v", err)
	}
	if c.Subject != hostiletest.Subject || c.Extra.Sub != "attacker" {
		t.Fatalf("subject = %q, extra.sub = %q; the payload leaked into the registered claims", c.Subject, c.Extra.Sub)
	}
}
