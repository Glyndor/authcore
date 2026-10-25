package jwt_test

import (
	"errors"
	"math"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/jwt"
)

// The module reads a real clock, so these tests place the token relative to
// the present with margins of a minute or more. A margin that wide keeps the
// outcome deterministic however slowly the test runs.
func TestHostile_Time_expiredAndMissingExpiryAreRefused(t *testing.T) {
	e := newEnv(t)
	m := e.module(t, jwt.Config{})
	now := time.Now()

	if _, err := m.VerifyAccessToken(e.signEdDSA(t, nil, with(claimsFor("access"), "exp", now.Add(time.Minute).Unix()))); err != nil {
		t.Fatalf("control: exp one minute ahead refused: %v", err)
	}

	for name, exp := range map[string]any{
		"exp two seconds ago":  now.Add(-2 * time.Second).Unix(),
		"exp an hour ago":      now.Add(-time.Hour).Unix(),
		"exp zero":             0,
		"exp minus one":        -1,
		"exp min int64":        int64(math.MinInt64),
		"exp epoch plus one":   1,
		"exp negative float":   -1.5e12,
		"exp fraction in past": float64(now.Add(-time.Hour).Unix()) + 0.5,
	} {
		t.Run(name, func(t *testing.T) {
			token := e.signEdDSA(t, nil, with(claimsFor("access"), "exp", exp))
			if c, err := m.VerifyAccessToken(token); c != nil || !errors.Is(err, jwt.ErrTokenExpired) {
				t.Fatalf("VerifyAccessToken = %+v, %v; want ErrTokenExpired", c, err)
			}
		})
	}

	token := e.signEdDSA(t, nil, with(claimsFor("access"), "exp", nil))
	if c, err := m.VerifyAccessToken(token); c != nil || !errors.Is(err, jwt.ErrTokenInvalid) {
		t.Fatalf("token without exp = %+v, %v; want ErrTokenInvalid", c, err)
	}
}

// Extreme and overflowing numbers must not wrap into a different date. The
// property is one-sided on purpose: whether a far-future exp is honoured is
// the issuer's policy, but a value too large for the date type must never be
// accepted as a date that is already past.
func TestHostile_Time_overflowingExpNeverWrapsIntoTheAcceptedPast(t *testing.T) {
	e := newEnv(t)
	m := e.module(t, jwt.Config{})
	for name, payloadExp := range map[string]string{
		"int64 max":          "9223372036854775807",
		"int64 max plus one": "9223372036854775808",
		"uint64 max":         "18446744073709551615",
		"2^64":               "18446744073709551616",
		"1e30":               "1e30",
		"1e308":              "1e308",
		"year 10000":         "253402300800",
		"negative 1e30":      "-1e30",
		"fractional far":     "9223372036.854775807",
		"leading plus":       "+1",
		"hex spelling":       "0x7fffffff",
		"exponent small":     "1e1",
	} {
		t.Run(name, func(t *testing.T) {
			now := time.Now().Unix()
			payload := `{"iss":"` + jwt.DefaultConfig().Issuer + `","aud":"` + jwt.DefaultConfig().Audience[0] + `","sub":"` + subject +
				`","jti":"` + jtiA + `","iat":` + itoa(now-1) + `,"exp":` + payloadExp + `,"type":"access"}`
			token := e.signRaw(t, payload)
			c, err := m.VerifyAccessToken(token)
			if c != nil && !c.ExpiresAt.After(time.Now()) {
				t.Fatalf("exp=%s was accepted with ExpiresAt=%v, which is not in the future", payloadExp, c.ExpiresAt)
			}
			if c == nil && err == nil {
				t.Fatal("no claims and no error")
			}
		})
	}
}

// nbf and iat in the future are refused; the leeway is the only slack and it
// is bounded.
func TestHostile_Time_futureTokensAndLeeway(t *testing.T) {
	e := newEnv(t)
	strict := e.module(t, jwt.Config{})
	lenient := e.module(t, jwt.Config{ClockSkewLeeway: 5 * time.Minute})
	now := time.Now()

	type tc struct {
		name   string
		key    string
		offset time.Duration
		strict bool // accepted with no leeway
		leeway bool // accepted with the 5 minute maximum leeway
	}
	for _, c := range []tc{
		{"iat 30s ahead", "iat", 30 * time.Second, false, true},
		{"iat 4m ahead", "iat", 4 * time.Minute, false, true},
		{"iat 6m ahead", "iat", 6 * time.Minute, false, false},
		{"iat 1h ahead", "iat", time.Hour, false, false},
		{"nbf 30s ahead", "nbf", 30 * time.Second, false, true},
		{"nbf 6m ahead", "nbf", 6 * time.Minute, false, false},
		{"nbf 1h ahead", "nbf", time.Hour, false, false},
		{"nbf 1h ago", "nbf", -time.Hour, true, true},
		{"exp 30s ago", "exp", -30 * time.Second, false, true},
		{"exp 4m ago", "exp", -4 * time.Minute, false, true},
		{"exp 6m ago", "exp", -6 * time.Minute, false, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			token := e.signEdDSA(t, nil, with(claimsFor("access"), c.key, now.Add(c.offset).Unix()))
			if _, err := strict.VerifyAccessToken(token); (err == nil) != c.strict {
				t.Errorf("no leeway: err=%v, want accepted=%v", err, c.strict)
			}
			if _, err := lenient.VerifyAccessToken(token); (err == nil) != c.leeway {
				t.Errorf("5m leeway: err=%v, want accepted=%v", err, c.leeway)
			}
		})
	}
}

// Leeway is the knob an operator turns when clocks drift, and the one an
// attacker would like turned all the way up. The module caps it.
func TestHostile_Time_leewayIsCappedAtConstruction(t *testing.T) {
	e := newEnv(t)
	if _, err := jwt.New[extra](e.prov, jwt.Config{ClockSkewLeeway: 5 * time.Minute}); err != nil {
		t.Fatalf("the maximum leeway was refused: %v", err)
	}
	for name, leeway := range map[string]time.Duration{
		"one nanosecond over": 5*time.Minute + time.Nanosecond,
		"an hour":             time.Hour,
		"max duration":        time.Duration(math.MaxInt64),
		"negative":            -time.Second,
		"min duration":        time.Duration(math.MinInt64),
	} {
		_, err := jwt.New[extra](e.prov, jwt.Config{ClockSkewLeeway: leeway})
		if !errors.Is(err, jwt.ErrInvalidConfig) {
			t.Errorf("%s: jwt.New = %v, want ErrInvalidConfig", name, err)
		}
	}
}

// Lifetimes the issuer would never mint are refused at construction, so a
// misconfiguration cannot turn into a token that outlives its purpose.
func TestHostile_Time_lifetimesAreCappedAtConstruction(t *testing.T) {
	e := newEnv(t)
	for name, cfg := range map[string]jwt.Config{
		"access over a day":        {AccessTokenTTL: 24*time.Hour + time.Nanosecond, RefreshTokenTTL: 365 * 24 * time.Hour},
		"access negative":          {AccessTokenTTL: -time.Minute},
		"access sub-second":        {AccessTokenTTL: time.Millisecond},
		"refresh over a year":      {RefreshTokenTTL: 365*24*time.Hour + time.Nanosecond},
		"refresh not above access": {AccessTokenTTL: time.Hour, RefreshTokenTTL: time.Hour},
		"refresh below access":     {AccessTokenTTL: time.Hour, RefreshTokenTTL: time.Minute},
		"refresh max duration":     {RefreshTokenTTL: time.Duration(math.MaxInt64)},
		"audience whitespace":      {Audience: []string{" "}},
		"audience invalid utf8":    {Audience: []string{"\xff"}},
		"issuer invalid utf8":      {Issuer: "\xff"},
	} {
		if _, err := jwt.New[extra](e.prov, cfg); !errors.Is(err, jwt.ErrInvalidConfig) {
			t.Errorf("%s: jwt.New = %v, want ErrInvalidConfig", name, err)
		}
	}
	if _, err := jwt.New[extra](e.prov, jwt.Config{AccessTokenTTL: 24 * time.Hour, RefreshTokenTTL: 365 * 24 * time.Hour}); err != nil {
		t.Errorf("the maximum lifetimes were refused: %v", err)
	}
}

// An expired refresh token cannot be rotated, even when its signature and
// type are right.
func TestHostile_Time_expiredRefreshTokenCannotRotate(t *testing.T) {
	e := newEnv(t)
	m := e.module(t, jwt.Config{})
	token := e.signEdDSA(t, nil, with(claimsFor("refresh"), "exp", time.Now().Add(-time.Hour).Unix()))
	if p, err := m.RotateTokens(token, extra{}); p != nil || !errors.Is(err, jwt.ErrTokenExpired) {
		t.Fatalf("RotateTokens = %+v, %v; want ErrTokenExpired", p, err)
	}
}
