package hostiletest_test

import (
	"runtime"
	"testing"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/email"
	"github.com/Glyndor/authcore/auth/username"
	"github.com/Glyndor/authcore/tests/hostile/identity/hostiletest"
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

func TestNewProviderHoldsAUsableKeyPair(t *testing.T) {
	p := hostiletest.NewProvider(t)
	k := p.Keys()
	if len(k.PrivateKey()) == 0 || len(k.PublicKey()) == 0 || len(k.RefreshSecret()) != 32 || k.KeyID() != "test" {
		t.Fatalf("unexpected key material: %d/%d/%d/%q", len(k.PrivateKey()), len(k.PublicKey()), len(k.RefreshSecret()), k.KeyID())
	}
	if p.Config().KeysDir != authcore.DefaultConfig().KeysDir {
		t.Fatal("provider config is not the default one")
	}
	l := p.Logger()
	l.Debug("x")
	l.Info("x")
	l.Warn("x")
	l.Error("x")
}

func TestNewEmailHonoursTheConfig(t *testing.T) {
	if _, err := hostiletest.NewEmail(t).ValidateAndNormalize("a+b@example.com"); err != nil {
		t.Fatalf("default module refused plus addressing: %v", err)
	}
	m := hostiletest.NewEmail(t, email.Config{RejectPlusAddressing: true})
	if _, err := m.ValidateAndNormalize("a+b@example.com"); err == nil {
		t.Fatal("configured module accepted plus addressing")
	}
}

func TestNewUsernameHonoursTheConfig(t *testing.T) {
	if _, err := hostiletest.NewUsername(t).ValidateAndNormalize("abcd"); err != nil {
		t.Fatalf("default module refused abcd: %v", err)
	}
	m := hostiletest.NewUsername(t, username.Config{MinLength: 5, MaxLength: 8})
	if _, err := m.ValidateAndNormalize("abcd"); err == nil {
		t.Fatal("configured module accepted a short name")
	}
	if !fails(func(tb testing.TB) { hostiletest.NewUsername(tb, username.Config{MinLength: -1}) }) {
		t.Fatal("an invalid config did not fail the helper")
	}
}
