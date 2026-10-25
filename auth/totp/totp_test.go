package totp

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/totp/internal/hotp"
	"github.com/Glyndor/authcore/auth/totp/internal/secret"
)

// ---- test infrastructure ----------------------------------------------------

type fakeKeys struct {
	secret []byte
}

func (fakeKeys) PrivateKey() ed25519.PrivateKey { return nil }
func (fakeKeys) PublicKey() ed25519.PublicKey   { return nil }
func (k fakeKeys) RefreshSecret() []byte        { return k.secret }
func (fakeKeys) KeyID() string                  { return "test" }

type fakeProvider struct{ keys authcore.Keys }

func (fakeProvider) Config() authcore.Config { return authcore.DefaultConfig() }
func (fakeProvider) Logger() authcore.Logger { return silentLogger{} }
func (p fakeProvider) Keys() authcore.Keys   { return p.keys }

type silentLogger struct{}

func (silentLogger) Debug(string, ...any) {}
func (silentLogger) Info(string, ...any)  {}
func (silentLogger) Warn(string, ...any)  {}
func (silentLogger) Error(string, ...any) {}

func newFakeProvider(tb testing.TB) fakeProvider {
	tb.Helper()
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		tb.Fatalf("generate test HMAC secret: %v", err)
	}
	return fakeProvider{keys: fakeKeys{secret: secret}}
}

// newTOTP creates a TOTP module on the real clock. The verification algorithm
// is exercised with a fixed clock in internal/verifier.
func newTOTP(tb testing.TB, cfg ...Config) *TOTP {
	tb.Helper()
	mod, err := New(newFakeProvider(tb), cfg...)
	if err != nil {
		tb.Fatalf("totp.New: %v", err)
	}
	return mod
}

// ---- Name / default config -------------------------------------------------

func TestName(t *testing.T) {
	m := newTOTP(t)
	if m.Name() != "totp" {
		t.Errorf("Name() = %q, want totp", m.Name())
	}
}

func TestNew_DefaultConfigSucceeds(t *testing.T) {
	_, err := New(newFakeProvider(t))
	if err != nil {
		t.Errorf("New() with default config returned error: %v", err)
	}
}

// stepStore is a minimal in-memory StepRecorder with the documented
// compare-and-advance semantics.
type stepStore struct {
	step uint64
	err  error
}

func (r *stepStore) RecordIfNewer(_ context.Context, step uint64) error {
	if r.err != nil {
		return r.err
	}
	if step <= r.step {
		return ErrCodeReused
	}
	r.step = step
	return nil
}

// The facade wires the real clock and the configured skew into the verifier
// and maps its refusals onto the exported sentinels. The algorithm itself is
// tested with a fixed clock in internal/verifier; this runs on the real one.
func TestVerify_throughTheFacade(t *testing.T) {
	mod := newTOTP(t)
	enr, err := mod.Enroll("alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	key, err := secret.Decode(enr.Secret)
	if err != nil {
		t.Fatal(err)
	}
	now := uint64(time.Now().Unix()) / hotp.TimeStep
	code := hotp.Generate(key, now)

	// The default skew of one step accepts the current code on either side of
	// a step boundary.
	rec := &stepStore{}
	if err := mod.Verify(context.Background(), enr.Secret, code, rec); err != nil {
		t.Fatalf("Verify of the current code: %v", err)
	}
	if rec.step < now-1 || rec.step > now+1 {
		t.Errorf("recorded step %d, want within one of %d", rec.step, now)
	}
	if err := mod.Verify(context.Background(), enr.Secret, code, rec); !errors.Is(err, ErrCodeReused) {
		t.Errorf("Verify of the same code twice: %v, want ErrCodeReused", err)
	}
	boom := errors.New("storage down")
	err = mod.Verify(context.Background(), enr.Secret, code, &stepStore{err: boom})
	if !errors.Is(err, boom) || !strings.Contains(err.Error(), "totp: record step:") {
		t.Errorf("Verify with a failing recorder: %v, want it wrapped with %q", err, "totp: record step:")
	}
	if err := mod.Verify(context.Background(), enr.Secret, code, nil); !errors.Is(err, ErrStepRecorderRequired) {
		t.Errorf("Verify with a nil recorder: %v, want ErrStepRecorderRequired", err)
	}

	for name, tc := range map[string]struct {
		secret, code string
		want         error
	}{
		"malformed code": {enr.Secret, "12345", ErrMalformedCode},
		"invalid secret": {"!!!!!!!!", code, ErrInvalidSecret},
		"stale code":     {enr.Secret, hotp.Generate(key, now-50), ErrInvalidCode},
	} {
		if _, err := mod.VerifyStep(tc.secret, tc.code, 0); !errors.Is(err, tc.want) {
			t.Errorf("%s: VerifyStep = %v, want %v", name, err, tc.want)
		}
	}
	step, err := mod.VerifyStep(enr.Secret, code, 0)
	if err != nil {
		t.Fatalf("VerifyStep of the current code: %v", err)
	}
	if _, err := mod.VerifyStep(enr.Secret, code, step); !errors.Is(err, ErrCodeReused) {
		t.Errorf("VerifyStep at the step it returned: %v, want ErrCodeReused", err)
	}
}
