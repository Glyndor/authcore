package hostiletest_test

import (
	"runtime"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/password"
	"github.com/Glyndor/authcore/tests/hostile/password/hostiletest"
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

func TestModuleHashesAndVerifiesTheStrongPassword(t *testing.T) {
	m := hostiletest.NewModule(t, hostiletest.LowCost())
	hash, err := m.Hash(hostiletest.Strong)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := m.Verify(hostiletest.Strong, hash)
	if err != nil || !ok {
		t.Fatalf("Verify = %v, %v", ok, err)
	}
}

func TestNewModuleFailsOnAnInvalidConfig(t *testing.T) {
	if !fails(func(tb testing.TB) { hostiletest.NewModule(tb, password.Config{Memory: 1}) }) {
		t.Fatal("an invalid config did not fail the helper")
	}
}

func TestPartsAndJoinRoundTrip(t *testing.T) {
	m := hostiletest.NewModule(t, hostiletest.LowCost())
	hash, err := m.Hash(hostiletest.Strong)
	if err != nil {
		t.Fatal(err)
	}
	if got := hostiletest.Join(hostiletest.Parts(t, hash)...); got != hash {
		t.Fatalf("Join(Parts(h)) = %q, want %q", got, hash)
	}
	if !fails(func(tb testing.TB) { hostiletest.Parts(tb, "not-a-hash") }) {
		t.Fatal("a malformed hash did not fail Parts")
	}
}

func TestEncIsUnpaddedBase64OfZeroBytes(t *testing.T) {
	if got := hostiletest.Enc(3); got != "AAAA" {
		t.Fatalf("Enc(3) = %q", got)
	}
	if strings.Contains(hostiletest.Enc(1), "=") {
		t.Fatal("Enc padded its output")
	}
}

func TestRelaxedDropsTheCompositionRules(t *testing.T) {
	cfg := hostiletest.Relaxed(20)
	if cfg.MinLength != 8 || cfg.MaxLength != 20 {
		t.Fatalf("lengths = %d..%d", cfg.MinLength, cfg.MaxLength)
	}
	m := hostiletest.NewModule(t, cfg)
	if _, err := m.Hash("alllowercase"); err != nil {
		t.Fatalf("relaxed config refused a plain password: %v", err)
	}
}

func TestRefHashIsAHashTheModuleVerifies(t *testing.T) {
	cfg := hostiletest.LowCost()
	hash := hostiletest.RefHash(hostiletest.Strong, cfg.Memory, uint32(cfg.Iterations), uint8(cfg.Parallelism), []byte("0123456789abcdef"))
	m := hostiletest.NewModule(t, cfg)
	ok, err := m.Verify(hostiletest.Strong, hash)
	if err != nil || !ok {
		t.Fatalf("module rejected the reference hash %q: %v, %v", hash, ok, err)
	}
}
