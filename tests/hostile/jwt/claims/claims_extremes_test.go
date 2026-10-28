package claims

import (
	"errors"
	"math"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/jwt"
	"github.com/Glyndor/authcore/tests/hostile/jwt/hostiletest"
)

// roundTrip issues a token carrying v as the extra claim and returns what
// VerifyAccessToken reads back.
func roundTrip[T any](t *testing.T, e *hostiletest.Env, v T) T {
	t.Helper()
	m, err := jwt.New[T](e.Prov)
	if err != nil {
		t.Fatalf("jwt.New: %v", err)
	}
	pair, err := m.CreateTokens(hostiletest.Subject, v)
	if err != nil {
		t.Fatalf("CreateTokens(%v): %v", v, err)
	}
	c, err := m.VerifyAccessToken(pair.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAccessToken(%v): %v", v, err)
	}
	return c.Extra
}

// The extra claim keeps 64-bit integers exact at both ends of their range and
// floats at theirs. A parser that went through float64 would round
// 9223372036854775807 to 9223372036854775808.
func TestHostile_ClaimExtremes_numbersInExtraRoundTripExactly(t *testing.T) {
	e := hostiletest.NewEnv(t)
	for _, v := range []int64{math.MaxInt64, math.MinInt64, math.MaxInt64 - 1, 1<<53 + 1, -(1<<53 + 1), 0} {
		if got := roundTrip(t, e, v); got != v {
			t.Errorf("int64 %d came back as %d", v, got)
		}
	}
	for _, v := range []uint64{math.MaxUint64, 1<<53 + 1, 0} {
		if got := roundTrip(t, e, v); got != v {
			t.Errorf("uint64 %d came back as %d", v, got)
		}
	}
	for _, v := range []float64{math.MaxFloat64, math.SmallestNonzeroFloat64, -math.MaxFloat64, 0.1, 1e21, 1e-7} {
		if got := roundTrip(t, e, v); got != v {
			t.Errorf("float64 %g came back as %g", v, got)
		}
	}
}

// A signed payload whose extra is a number outside the module's type is refused
// instead of wrapping or saturating.
func TestHostile_ClaimExtremes_outOfRangeNumbersInExtraAreRefused(t *testing.T) {
	e := hostiletest.NewEnv(t)
	now := time.Now().Unix()
	payload := func(extraJSON string) string {
		return `{"iss":"` + jwt.DefaultConfig().Issuer + `","aud":"` + jwt.DefaultConfig().Audience[0] + `","sub":"` + hostiletest.Subject +
			`","jti":"` + hostiletest.JtiA + `","iat":` + strconv.FormatInt(now-1, 10) + `,"exp":` + strconv.FormatInt(now+600, 10) +
			`,"type":"access","extra":` + extraJSON + `}`
	}
	i64, err := jwt.New[int64](e.Prov)
	if err != nil {
		t.Fatal(err)
	}
	i8, _ := jwt.New[int8](e.Prov)
	f64, _ := jwt.New[float64](e.Prov)
	for name, tc := range map[string]struct {
		verify func(string) error
		extra  string
	}{
		"int64 max plus one":  {func(s string) error { _, err := i64.VerifyAccessToken(s); return err }, "9223372036854775808"},
		"int64 min minus one": {func(s string) error { _, err := i64.VerifyAccessToken(s); return err }, "-9223372036854775809"},
		"int64 fraction":      {func(s string) error { _, err := i64.VerifyAccessToken(s); return err }, "1.5"},
		"int64 exponent":      {func(s string) error { _, err := i64.VerifyAccessToken(s); return err }, "1e3"},
		"int64 string":        {func(s string) error { _, err := i64.VerifyAccessToken(s); return err }, `"5"`},
		"int8 128":            {func(s string) error { _, err := i8.VerifyAccessToken(s); return err }, "128"},
		"float64 1e999":       {func(s string) error { _, err := f64.VerifyAccessToken(s); return err }, "1e999"},
		"float64 string":      {func(s string) error { _, err := f64.VerifyAccessToken(s); return err }, `"NaN"`},
	} {
		if err := tc.verify(e.SignRaw(t, payload(tc.extra))); !errors.Is(err, jwt.ErrTokenMalformed) {
			t.Errorf("%s: payload with extra=%s: got %v, want ErrTokenMalformed", name, tc.extra, err)
		}
	}
}

// Issuing refuses values the JSON encoding cannot carry, with an error and no
// token, rather than a token that reads back as something else.
func TestHostile_ClaimExtremes_unencodableExtraProducesNoToken(t *testing.T) {
	e := hostiletest.NewEnv(t)
	m, err := jwt.New[float64](e.Prov)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		if p, err := m.CreateTokens(hostiletest.Subject, v); p != nil || err == nil {
			t.Errorf("CreateTokens(%v) = %v, %v; want an error and no pair", v, p, err)
		}
	}
}

// The audience claim is bounded by the token size limit, not by luck. A token
// whose audience array is enormous is refused as oversized before it is
// parsed; one that fits and names our audience last still verifies; and a
// configuration whose audience cannot fit in a token cannot issue one.
func TestHostile_ClaimExtremes_audienceArraySizeIsBounded(t *testing.T) {
	e := hostiletest.NewEnv(t)
	m := e.Module(t, jwt.Config{})
	ours := jwt.DefaultConfig().Audience[0]

	build := func(n int) string {
		aud := make([]any, 0, n+1)
		for i := 0; i < n; i++ {
			aud = append(aud, "a"+strconv.Itoa(i))
		}
		return e.SignEdDSA(t, nil, hostiletest.With(hostiletest.ClaimsFor("access"), "aud", append(aud, ours)))
	}
	if _, err := m.VerifyAccessToken(build(400)); err != nil {
		t.Errorf("a 400-entry audience naming us last was refused: %v", err)
	}
	for _, n := range []int{5000, 200000} {
		token := build(n)
		start := time.Now()
		c, err := m.VerifyAccessToken(token)
		if c != nil || !errors.Is(err, jwt.ErrTokenOversized) {
			t.Errorf("%d-entry audience = %+v, %v; want ErrTokenOversized", n, c, err)
		}
		if d := time.Since(start); d > time.Second {
			t.Errorf("%d-entry audience took %s to refuse", n, d)
		}
	}

	big := make([]string, 0, 2000)
	for i := 0; i < 2000; i++ {
		big = append(big, strings.Repeat("x", 20)+strconv.Itoa(i))
	}
	huge, err := jwt.New[hostiletest.Extra](e.Prov, jwt.Config{Audience: big})
	if err != nil {
		return // refusing the configuration is also fine
	}
	if p, err := huge.CreateTokens(hostiletest.Subject, hostiletest.Extra{}); p != nil || !errors.Is(err, jwt.ErrTokenOversized) {
		t.Errorf("CreateTokens with a 2000-entry audience = %v, %v; want ErrTokenOversized", p, err)
	}
}
