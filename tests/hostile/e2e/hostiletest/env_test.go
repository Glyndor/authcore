package hostiletest_test

import (
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/credential"
	"github.com/Glyndor/authcore/auth/jwt"
	"github.com/Glyndor/authcore/auth/totp"
	"github.com/Glyndor/authcore/tests/hostile/e2e/hostiletest"
)

// fakeTB records a failure instead of ending the test, so the failure branch of
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

// fails reports whether fn ended its test through Fatal or Fatalf.
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

func TestEnv_buildsEveryModuleOverOneSecret(t *testing.T) {
	e := hostiletest.NewEnv(t)
	if len(e.Secret) != 32 || len(e.Priv) == 0 || len(e.Pub) == 0 {
		t.Fatal("deployment has no key material")
	}
	if e.JWT(t, jwt.Config{}) == nil || e.APIKey(t) == nil || e.Field(t, "email") == nil {
		t.Fatal("a module is nil")
	}
	if e.Credential(t, credential.DefaultConfig()) == nil || e.TOTP(t, totp.Config{}) == nil {
		t.Fatal("a module is nil")
	}
	other := hostiletest.NewEnv(t)
	if string(e.Secret) == string(other.Secret) {
		t.Error("two deployments share a secret")
	}
}

func TestCheck_endsTheTestOnlyOnAnError(t *testing.T) {
	if fails(func(tb testing.TB) { hostiletest.Check(tb, nil) }) {
		t.Error("Check(nil) failed the test")
	}
	if !fails(func(tb testing.TB) { hostiletest.Check(tb, errors.New("boom")) }) {
		t.Error("Check(err) did not fail the test")
	}
}

func TestAge_movesTheValidityWindowAndKeepsTheRest(t *testing.T) {
	e := hostiletest.NewEnv(t)
	m := e.JWT(t, jwt.Config{AccessTokenTTL: 10 * time.Minute, RefreshTokenTTL: time.Hour})
	pair, err := m.CreateTokens(hostiletest.Subject, hostiletest.Extra{Role: "user"})
	if err != nil {
		t.Fatal(err)
	}
	same := hostiletest.Age(t, e, pair.AccessToken, 0)
	if _, err := m.VerifyAccessToken(same); err != nil {
		t.Errorf("a token aged by zero seconds = %v, want accepted", err)
	}
	young := hostiletest.Age(t, e, pair.AccessToken, 9*time.Minute)
	if claims, err := m.VerifyAccessToken(young); err != nil || claims.TokenID != pair.SessionID {
		t.Errorf("a token aged by 9 minutes = %v, want accepted with its jti", err)
	}
	if _, err := m.VerifyAccessToken(hostiletest.Age(t, e, pair.AccessToken, 10*time.Minute)); !errors.Is(err, jwt.ErrTokenExpired) {
		t.Errorf("a token aged by its whole TTL = %v, want ErrTokenExpired", err)
	}
	foreign := hostiletest.Age(t, hostiletest.NewEnv(t), pair.AccessToken, 0)
	if _, err := m.VerifyAccessToken(foreign); err == nil {
		t.Error("a token re-signed by another key was accepted")
	}
}

func TestAge_refusesWhatIsNotAToken(t *testing.T) {
	e := hostiletest.NewEnv(t)
	for name, token := range map[string]string{
		"two segments":    "a.b",
		"payload not b64": "a.!!.c",
		"payload not obj": "a." + "WzFd" + ".c", // base64 of [1]
	} {
		if !fails(func(tb testing.TB) { hostiletest.Age(tb, e, token, time.Minute) }) {
			t.Errorf("%s: Age did not fail", name)
		}
	}
	if strings.Count(hostiletest.Age(t, e, "a.e30.c", time.Minute), ".") != 2 {
		t.Error("an empty payload object is not aged into three segments")
	}
}
