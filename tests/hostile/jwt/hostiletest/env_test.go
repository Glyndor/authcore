package hostiletest_test

import (
	"runtime"
	"strings"
	"testing"
	"time"

	gjwt "github.com/golang-jwt/jwt/v5"

	"github.com/Glyndor/authcore/auth/jwt"
	"github.com/Glyndor/authcore/tests/hostile/jwt/hostiletest"
)

// fakeTB records a Fatalf instead of ending the test, so the failure branch of
// a helper can be asserted.
type fakeTB struct {
	testing.TB
	failed bool
}

func (f *fakeTB) Helper() {}

func (f *fakeTB) Fatalf(string, ...any) {
	f.failed = true
	runtime.Goexit()
}

func (f *fakeTB) Fatal(...any) {
	f.failed = true
	runtime.Goexit()
}

func fails(fn func(tb testing.TB)) bool {
	f := &fakeTB{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn(f)
	}()
	<-done
	return f.failed
}

func TestEnvIssuesTokensItsReferenceVerifierAccepts(t *testing.T) {
	e := hostiletest.NewEnv(t)
	if e.Kid == "" {
		t.Fatal("Env has no kid")
	}
	pair, err := e.Module(t, jwt.Config{}).CreateTokens(hostiletest.Subject, hostiletest.Extra{Role: "r"})
	if err != nil {
		t.Fatal(err)
	}
	cfg := jwt.DefaultConfig()
	p := hostiletest.RefPolicy{Issuer: cfg.Issuer, Audience: cfg.Audience[0], Typ: "access", Kid: e.Kid, Pub: e.Pub, Now: time.Now()}
	if err := hostiletest.RefVerify(pair.AccessToken, p); err != nil {
		t.Fatalf("reference verifier rejected a module token: %v", err)
	}
}

func TestModuleFailsOnAnInvalidConfig(t *testing.T) {
	e := hostiletest.NewEnv(t)
	if !fails(func(tb testing.TB) { e.Module(tb, jwt.Config{AccessTokenTTL: -time.Second}) }) {
		t.Fatal("an invalid config did not fail the helper")
	}
}

func TestDecodeAndRebuildHeader(t *testing.T) {
	e := hostiletest.NewEnv(t)
	token := e.SignEdDSA(t, nil, hostiletest.ClaimsFor("access"))
	h := hostiletest.DecodeHeader(t, token)
	if h["alg"] != "EdDSA" || h["kid"] != e.Kid {
		t.Fatalf("header = %v", h)
	}
	h["kid"] = "other"
	rebuilt := hostiletest.RebuildHeader(t, token, h)
	if got := hostiletest.DecodeHeader(t, rebuilt)["kid"]; got != "other" {
		t.Fatalf("rebuilt kid = %v", got)
	}
	if strings.SplitN(rebuilt, ".", 2)[1] != strings.SplitN(token, ".", 2)[1] {
		t.Fatal("RebuildHeader changed payload or signature")
	}
	if !fails(func(tb testing.TB) { hostiletest.DecodeHeader(tb, "!!!.x.y") }) {
		t.Fatal("bad base64 did not fail DecodeHeader")
	}
	if !fails(func(tb testing.TB) { hostiletest.DecodeHeader(tb, hostiletest.B64("nope")+".x.y") }) {
		t.Fatal("bad JSON did not fail DecodeHeader")
	}
	if !fails(func(tb testing.TB) { hostiletest.RebuildHeader(tb, token, map[string]any{"x": make(chan int)}) }) {
		t.Fatal("an unencodable header did not fail RebuildHeader")
	}
}

func TestClaimsHelpers(t *testing.T) {
	c := hostiletest.ClaimsFor("refresh")
	if c["type"] != "refresh" || c["sub"] != hostiletest.Subject || c["jti"] != hostiletest.JtiA {
		t.Fatalf("claims = %v", c)
	}
	w := hostiletest.With(c, "type", "access")
	if w["type"] != "access" || c["type"] != "refresh" {
		t.Fatal("With did not copy")
	}
	if _, ok := hostiletest.With(c, "jti", nil)["jti"]; ok {
		t.Fatal("With(nil) did not delete")
	}
}

func TestSigningHelpers(t *testing.T) {
	e := hostiletest.NewEnv(t)
	m := e.Module(t, jwt.Config{})
	if _, err := m.VerifyAccessToken(e.SignEdDSA(t, nil, hostiletest.ClaimsFor("access"))); err != nil {
		t.Fatalf("module refused its own key's token: %v", err)
	}
	raw := e.SignRaw(t, `{"sub":"x"}`)
	if len(strings.Split(raw, ".")) != 3 {
		t.Fatalf("SignRaw = %q", raw)
	}
	tok := e.Sign(t, gjwt.SigningMethodEdDSA, e.Priv, map[string]any{"kid": nil, "x": "y"}, hostiletest.ClaimsFor("access"))
	h := hostiletest.DecodeHeader(t, tok)
	if _, ok := h["kid"]; ok || h["x"] != "y" {
		t.Fatalf("header overrides not applied: %v", h)
	}
	if !fails(func(tb testing.TB) {
		e.Sign(tb, gjwt.SigningMethodEdDSA, "not a key", nil, hostiletest.ClaimsFor("access"))
	}) {
		t.Fatal("a wrong key type did not fail Sign")
	}
	if hostiletest.Itoa(int64(-42)) != "-42" || hostiletest.B64("a?") != "YT8" {
		t.Fatal("Itoa or B64 wrong")
	}
}

func TestReferenceVerifierRules(t *testing.T) {
	e := hostiletest.NewEnv(t)
	cfg := jwt.DefaultConfig()
	p := hostiletest.RefPolicy{Issuer: cfg.Issuer, Audience: cfg.Audience[0], Typ: "access", Kid: e.Kid, Pub: e.Pub, Now: time.Now()}
	good := func() map[string]any { return hostiletest.ClaimsFor("access") }
	if err := hostiletest.RefVerify(e.SignEdDSA(t, nil, good()), p); err != nil {
		t.Fatalf("good token refused: %v", err)
	}
	cases := map[string]string{
		"segments":     "a.b",
		"header enc":   "!.e30.e30",
		"payload enc":  hostiletest.B64("{}") + ".!.e30",
		"sig enc":      hostiletest.B64("{}") + "." + hostiletest.B64("{}") + ".!",
		"header json":  hostiletest.B64("x") + "." + hostiletest.B64("{}") + ".e30",
		"alg":          e.Sign(t, gjwt.SigningMethodHS256, []byte("k"), nil, good()),
		"kid":          e.SignEdDSA(t, map[string]any{"kid": "zzz"}, good()),
		"signature":    e.Sign(t, gjwt.SigningMethodEdDSA, otherKey(t), nil, good()),
		"claims json":  e.SignRaw(t, "nope"),
		"iss":          e.SignEdDSA(t, nil, hostiletest.With(good(), "iss", "evil")),
		"aud":          e.SignEdDSA(t, nil, hostiletest.With(good(), "aud", []any{"x", 1})),
		"aud string":   e.SignEdDSA(t, nil, hostiletest.With(good(), "aud", 5)),
		"aud missing":  e.SignEdDSA(t, nil, hostiletest.With(good(), "aud", []any{"x"})),
		"sub":          e.SignEdDSA(t, nil, hostiletest.With(good(), "sub", "plain")),
		"type":         e.SignEdDSA(t, nil, hostiletest.With(good(), "type", "refresh")),
		"exp missing":  e.SignEdDSA(t, nil, hostiletest.With(good(), "exp", nil)),
		"exp range":    e.SignEdDSA(t, nil, hostiletest.With(good(), "exp", int64(-1))),
		"expired":      e.SignEdDSA(t, nil, hostiletest.With(good(), "exp", time.Now().Add(-time.Hour).Unix())),
		"iat future":   e.SignEdDSA(t, nil, hostiletest.With(good(), "iat", time.Now().Add(time.Hour).Unix())),
		"nbf shape":    e.SignEdDSA(t, nil, hostiletest.With(good(), "nbf", "soon")),
		"nbf future":   e.SignEdDSA(t, nil, hostiletest.With(good(), "nbf", time.Now().Add(time.Hour).Unix())),
		"exp fraction": e.SignRaw(t, `{"exp":1e999}`),
	}
	for name, token := range cases {
		if err := hostiletest.RefVerify(token, p); err == nil {
			t.Errorf("%s: reference verifier accepted the token", name)
		}
	}
	single := hostiletest.With(good(), "aud", cfg.Audience[0])
	if err := hostiletest.RefVerify(e.SignEdDSA(t, nil, single), p); err != nil {
		t.Fatalf("string audience refused: %v", err)
	}
}

func otherKey(t *testing.T) any {
	t.Helper()
	e := hostiletest.NewEnv(t)
	return e.Priv
}
