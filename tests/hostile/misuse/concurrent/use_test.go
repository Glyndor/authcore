// Package concurrent shares one module between many goroutines the way a web
// server does, and shares a Config between the caller and the module. Run with
// -race: a module that kept the caller's slice or pointer is a data race here
// before it is a wrong answer in production.
package concurrent

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/apikey"
	"github.com/Glyndor/authcore/auth/credential"
	"github.com/Glyndor/authcore/auth/email"
	"github.com/Glyndor/authcore/auth/field"
	"github.com/Glyndor/authcore/auth/jwt"
	"github.com/Glyndor/authcore/auth/password"
	"github.com/Glyndor/authcore/auth/totp"
	"github.com/Glyndor/authcore/auth/username"
	"github.com/Glyndor/authcore/tests/hostile/misuse/hostiletest"
)

const workers = 16

// fanOut runs fn on workers goroutines released together.
func fanOut(fn func(i int)) {
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			fn(i)
		}()
	}
	close(start)
	wg.Wait()
}

// One TOTP code presented by many goroutines at once is accepted exactly once.
func TestMisuse_Concurrent_totpCodeIsAcceptedExactlyOnce(t *testing.T) {
	e := hostiletest.NewEnv(t)
	m, _ := totp.New(e.AC)
	enr, err := m.Enroll("ana@example.com")
	if err != nil {
		t.Fatal(err)
	}
	code := hostiletest.TOTPCode(t, enr.Secret, time.Now())
	rec := &hostiletest.Recorder{}
	var ok, reused, other atomic.Int32
	fanOut(func(int) {
		switch err := m.Verify(context.Background(), enr.Secret, code, rec); {
		case err == nil:
			ok.Add(1)
		case errors.Is(err, totp.ErrCodeReused):
			reused.Add(1)
		default:
			other.Add(1)
		}
	})
	if ok.Load() != 1 || reused.Load() != workers-1 || other.Load() != 0 {
		t.Fatalf("accepted %d, reused %d, other %d of %d", ok.Load(), reused.Load(), other.Load(), workers)
	}
}

// Everything a module hands out once is unique under concurrency.
func TestMisuse_Concurrent_issuedValuesAreUnique(t *testing.T) {
	e := hostiletest.NewEnv(t)
	j, _ := jwt.New[struct{}](e.AC)
	ak, _ := apikey.New(e.AC)
	tp, _ := totp.New(e.AC)
	cr, _ := credential.New(e.AC)

	var mu sync.Mutex
	seen := map[string]string{}
	record := func(kind, v string) {
		mu.Lock()
		defer mu.Unlock()
		if prev, dup := seen[v]; dup {
			t.Errorf("%s value repeats one issued as %s", kind, prev)
		}
		seen[v] = kind
	}
	fanOut(func(int) {
		for range 8 {
			p, err := j.CreateTokens(hostiletest.Subject, struct{}{})
			if err != nil {
				t.Error(err)
				return
			}
			record("jwt access", p.AccessToken)
			record("jwt refresh", p.RefreshToken)
			g, _ := ak.Generate()
			record("api key", g.Key)
			en, _ := tp.Enroll("ana")
			record("totp secret", en.Secret)
			is, _ := cr.Issue("reset", hostiletest.Subject)
			record("credential", is.Token)
		}
	})
}

// Every stateless module is used by many goroutines at once with the same
// inputs and gives the same answers.
func TestMisuse_Concurrent_sharedModulesGiveStableAnswers(t *testing.T) {
	e := hostiletest.NewEnv(t)
	j, _ := jwt.New[struct{}](e.AC)
	pw, _ := password.New(e.AC, password.Config{Memory: 8 * 1024, Iterations: 1})
	ak, _ := apikey.New(e.AC)
	cr, _ := credential.New(e.AC)
	fd, _ := field.New(e.AC, field.Config{Context: "users.email"})
	em, _ := email.New(e.AC)
	un, _ := username.New(e.AC)

	pair, _ := j.CreateTokens(hostiletest.Subject, struct{}{})
	hash, _ := pw.Hash("Correct-Horse-9-Battery-Staple")
	g, _ := ak.Generate()
	iss, _ := cr.Issue("reset", hostiletest.Subject)
	ct, _ := fd.Encrypt("ana@example.com")

	fanOut(func(i int) {
		if _, err := j.VerifyAccessToken(pair.AccessToken); err != nil {
			t.Errorf("jwt: %v", err)
		}
		if _, err := j.VerifyAccessToken(pair.RefreshToken); err == nil {
			t.Error("jwt accepted a refresh token")
		}
		if ok, err := pw.Verify("Correct-Horse-9-Battery-Staple", hash); !ok || err != nil {
			t.Errorf("password: %v %v", ok, err)
		}
		if !ak.Verify(g.Key, g.Hash) || ak.Verify(g.Key, "00") {
			t.Error("apikey answers changed")
		}
		if err := cr.Verify("reset", hostiletest.Subject, iss.Token, iss.Hash, time.Now()); err != nil {
			t.Errorf("credential: %v", err)
		}
		if got, err := fd.Decrypt(ct); got != "ana@example.com" || err != nil {
			t.Errorf("field: %q %v", got, err)
		}
		if got, err := em.ValidateAndNormalize("Ana@Example.com"); got != "ana@example.com" || err != nil {
			t.Errorf("email: %q %v", got, err)
		}
		if _, err := un.ValidateAndNormalize("admin"); err == nil {
			t.Error("username accepted a reserved name")
		}
		_ = e.AC.Config()
		_ = e.AC.Logger()
		_ = e.AC.Keys().KeyID()
		_ = i
	})
}

// The caller keeps editing the Config it passed while the module is in use.
// The module holds no reference to it, which the race detector would show.
func TestMisuse_Concurrent_callerEditsItsConfigWhileTheModuleRuns(t *testing.T) {
	e := hostiletest.NewEnv(t)
	jcfg := jwt.Config{Audience: []string{"aud-a"}}
	j, err := jwt.New[struct{}](e.AC, jcfg)
	if err != nil {
		t.Fatal(err)
	}
	pcfg := password.Config{Memory: 8 * 1024, Iterations: 1, RequireSymbol: password.Bool(true)}
	pw, err := password.New(e.AC, pcfg)
	if err != nil {
		t.Fatal(err)
	}
	tcfg := totp.Config{SkewSteps: totp.Int(1)}
	tp, err := totp.New(e.AC, tcfg)
	if err != nil {
		t.Fatal(err)
	}
	ucfg := username.Config{ExtraReservedNames: []string{"zzfoo"}}
	un, err := username.NewWithConfig(e.AC, ucfg)
	if err != nil {
		t.Fatal(err)
	}

	stop := make(chan struct{})
	var editor sync.WaitGroup
	editor.Add(1)
	go func() {
		defer editor.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			jcfg.Audience[0] = "aud-evil"
			*pcfg.RequireSymbol = false
			*tcfg.SkewSteps = 10
			ucfg.ExtraReservedNames[0] = "zzbar"
		}
	}()
	enr, _ := tp.Enroll("ana")
	fanOut(func(int) {
		for range 20 {
			p, err := j.CreateTokens(hostiletest.Subject, struct{}{})
			if err != nil {
				t.Error(err)
				return
			}
			if _, err := j.VerifyAccessToken(p.AccessToken); err != nil {
				t.Errorf("verify: %v", err)
			}
			_ = pw.ValidatePolicy("Abcdefghijklmnop1")
			_, _ = tp.VerifyStep(enr.Secret, "000000", 0)
			_, _ = un.ValidateAndNormalize("zzfoo")
		}
	})
	close(stop)
	editor.Wait()
}
