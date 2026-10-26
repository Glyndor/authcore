package hostiletest_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/jwt"
	"github.com/Glyndor/authcore/auth/totp"
	"github.com/Glyndor/authcore/tests/hostile/misuse/hostiletest"
)

// fakeTB records an Errorf instead of failing the test, so the failure branch
// of an assertion helper can itself be asserted.
type fakeTB struct {
	testing.TB
	errors int
}

func (f *fakeTB) Helper()               {}
func (f *fakeTB) Errorf(string, ...any) { f.errors++ }

func TestMaterialCloneIsDeep(t *testing.T) {
	m := hostiletest.NewMaterial(t)
	c := m.Clone()
	if !bytes.Equal(m.Priv, c.Priv) || !bytes.Equal(m.Pub, c.Pub) || !bytes.Equal(m.Secret, c.Secret) {
		t.Fatal("clone differs from the original")
	}
	c.Secret[0] ^= 0xff
	c.Priv[0] ^= 0xff
	c.Pub[0] ^= 0xff
	if bytes.Equal(m.Secret, c.Secret) || bytes.Equal(m.Priv, c.Priv) || bytes.Equal(m.Pub, c.Pub) {
		t.Fatal("clone shares memory with the original")
	}
	if len(m.Secret) != 32 || len(m.Priv) != 64 || len(m.Pub) != 32 {
		t.Fatalf("sizes %d %d %d", len(m.Secret), len(m.Priv), len(m.Pub))
	}
}

func TestEnvBuildsAWorkingAuthCoreAndRecordsLogs(t *testing.T) {
	e := hostiletest.NewEnv(t)
	if !bytes.Equal(e.AC.Keys().RefreshSecret(), e.Mat.Secret) {
		t.Fatal("the Env secret is not the one the AuthCore holds")
	}
	e.Log.Debug("d %d", 1)
	e.Log.Info("i %s", "x")
	e.Log.Warn("w")
	e.Log.Error("e")
	text := e.Log.Text()
	for _, want := range []string{"d 1", "i x", "w", "e", "authcore initialised"} {
		if !strings.Contains(text, want) {
			t.Errorf("log text lacks %q", want)
		}
	}
}

func TestProviderServesModulesAndAnswersNilForMissingKeys(t *testing.T) {
	p, mat := hostiletest.NewProvider(t)
	if _, err := jwt.New[struct{}](p); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p.Keys().RefreshSecret(), mat.Secret) || p.Keys().KeyID() != "misuse-kid" {
		t.Fatal("provider keys differ from the material")
	}
	if p.Config().Timezone != authcore.DefaultConfig().Timezone || p.Logger() == nil {
		t.Fatal("provider config or logger missing")
	}
	if !bytes.Equal(p.K.PublicKey(), mat.Pub) || !bytes.Equal(p.K.PrivateKey(), mat.Priv) {
		t.Fatal("key accessors differ from the material")
	}
	p.K = nil
	if p.Keys() != nil {
		t.Fatal("a provider with no keys must answer with a nil interface")
	}
}

func TestPanicsReportsAndNoPanicFails(t *testing.T) {
	if p, _ := hostiletest.Panics(func() {}); p {
		t.Fatal("reported a panic that did not happen")
	}
	p, v := hostiletest.Panics(func() { panic("boom") })
	if !p || v != "boom" {
		t.Fatalf("got %v %v", p, v)
	}
	f := &fakeTB{}
	hostiletest.NoPanic(f, "quiet", func() {})
	if f.errors != 0 {
		t.Fatal("NoPanic failed on a quiet function")
	}
	hostiletest.NoPanic(f, "loud", func() { panic("x") })
	if f.errors != 1 {
		t.Fatal("NoPanic did not fail on a panic")
	}
}

func TestLeakDetectionFindsEverySpelling(t *testing.T) {
	secret := []byte("0123456789abcdef-printable-secret")
	random := hostiletest.NewMaterial(t).Secret
	for name, out := range map[string]string{
		"raw text":     "x " + string(secret[:12]) + " y",
		"decimal list": "[48 49 50 51 52 53 54 55 56 57 97 98]",
		"hex list":     "0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62",
		"plain hex":    "303132333435363738396162",
	} {
		if len(hostiletest.Leaks(out, secret)) == 0 {
			t.Errorf("%s was not found", name)
		}
	}
	if len(hostiletest.Leaks("nothing to see", secret, random)) != 0 {
		t.Error("reported a leak in clean text")
	}
	if len(hostiletest.Forms(random)) != 5 {
		t.Error("a random secret should yield the five byte spellings only")
	}
	if len(hostiletest.Forms([]byte("printable"))) < 6 {
		t.Error("a short printable secret should add its raw text")
	}
	f := &fakeTB{}
	hostiletest.NoLeak(f, "clean", "nothing", secret)
	hostiletest.NoLeak(f, "dirty", string(secret), secret)
	if f.errors != 1 {
		t.Fatalf("NoLeak failed %d times, want 1", f.errors)
	}
}

func TestPEMInputsBuildAKeyStore(t *testing.T) {
	priv, pub, secret := hostiletest.NewPEM(t)
	if _, err := authcore.NewKeyStoreFromPEM(priv, pub, secret); err != nil {
		t.Fatal(err)
	}
}

func TestTOTPCodeMatchesTheLibrary(t *testing.T) {
	e := hostiletest.NewEnv(t)
	m, err := totp.New(e.AC)
	if err != nil {
		t.Fatal(err)
	}
	enr, err := m.Enroll("ana@example.com")
	if err != nil {
		t.Fatal(err)
	}
	code := hostiletest.TOTPCode(t, enr.Secret, time.Now())
	if _, err := m.VerifyStep(enr.Secret, code, 0); err != nil {
		t.Fatalf("the reference code is refused: %v", err)
	}
}

func TestRecorderAcceptsOnlyNewerSteps(t *testing.T) {
	r := &hostiletest.Recorder{}
	ctx := context.Background()
	if err := r.RecordIfNewer(ctx, 5); err != nil {
		t.Fatal(err)
	}
	for _, step := range []uint64{5, 4} {
		if err := r.RecordIfNewer(ctx, step); !errors.Is(err, totp.ErrCodeReused) {
			t.Errorf("step %d: %v", step, err)
		}
	}
	if err := r.RecordIfNewer(ctx, 6); err != nil || r.Calls != 4 {
		t.Fatalf("step 6: %v, %d calls", err, r.Calls)
	}
}
