package totp

// Internal test package (package totp, not package totp_test) so that the
// clock can be replaced with clock.Fixed and the test secrets generated
// from raw bytes match what the production code base32-decodes back. This
// matches the pattern in auth/jwt where time-sensitive tests live inside
// the package's own test scope.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"testing"
	"time"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/internal/clock"
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

// epoch is a fixed reference time used across tests that need a known
// "now" without sleeping.
var epoch = time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)

// newTOTP creates a TOTP module with a fixed clock pinned to epoch.
func newTOTP(tb testing.TB, cfg ...Config) *TOTP {
	tb.Helper()
	mod, err := New(newFakeProvider(tb), cfg...)
	if err != nil {
		tb.Fatalf("totp.New: %v", err)
	}
	mod.clock = clock.Fixed(epoch)
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

// ---- RFC 6238 Appendix B test vectors ---------------------------------------
//
// The reference secret is the 20 ASCII bytes of "12345678901234567890".
// Verify must accept the published (time, code) triples for HMAC-SHA1.
// These are the only assertions that check the implementation against
// the standard rather than against itself, so they are mandatory.

const rfcSecretASCII = "12345678901234567890"

// rfcSecretB32 is rfcSecretASCII encoded as base32 without padding.
// 20 bytes -> 32 base32 chars exactly.
var rfcSecretB32 = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(rfcSecretASCII))

// rfcVectors is the RFC 6238 Appendix B HMAC-SHA1 test vector table.
//
// The published TOTP column in the RFC is 8-digit (the RFC's chosen
// digit count). The module under test enforces the closed interop
// baseline of 6 digits (digits=6) per docs/configuration.md: a
// configurable value here would lock the user out of every
// widely-used authenticator app, so the module ships one value. The
// 8-digit codes are kept in the table for reference; code6 is the
// 6-digit equivalent computed as the RFC's HOTP truncated value mod
// 10^6, zero-padded - the HMAC and dynamic truncation are identical,
// only the final mod differs.
//
// For each (time, secret) pair, Verify MUST succeed with code6 and
// the returned step MUST equal time/30. If a vector does not pass,
// the implementation is wrong; do not edit the table.
var rfcVectors = []struct {
	name  string
	time  int64
	code8 string // RFC 6238 Appendix B published value (8 digits)
	code6 string // 6-digit equivalent (mod 10^6, zero-padded)
}{
	{"step 1 (T=59)", 59, "94287082", "287082"},
	{"step 37037036 (T=1111111109)", 1111111109, "07081804", "081804"},
	{"step 37037037 (T=1111111111)", 1111111111, "14050471", "050471"},
	{"step 41152263 (T=1234567890)", 1234567890, "89005924", "005924"},
	{"step 66666666 (T=2000000000)", 2000000000, "69279037", "279037"},
	{"step 666666666 (T=20000000000)", 20000000000, "65353130", "353130"},
}

func TestVerify_RFC6238AppendixB(t *testing.T) {
	mod := newTOTP(t, Config{SkewSteps: Int(0)}) // exact match only
	for _, v := range rfcVectors {
		t.Run(v.name, func(t *testing.T) {
			mod.clock = clock.Fixed(time.Unix(v.time, 0).UTC())
			step, err := mod.VerifyStep(rfcSecretB32, v.code6, 0)
			if err != nil {
				t.Fatalf("Verify(%q) at t=%d (RFC %s) returned err=%v, want nil",
					v.code6, v.time, v.code8, err)
			}
			want := uint64(v.time) / timeStep
			if step != want {
				t.Errorf("Verify(%q) at t=%d returned step=%d, want %d",
					v.code6, v.time, step, want)
			}
		})
	}
}

// rfcVectorsSkew1 is the same set but with a generous skew window so a
// subclass of bugs (off-by-one in the window calculation) cannot mask a
// failing vector. The published codes are computed at the step itself,
// so they sit at the centre of the window and must still verify.
func TestVerify_RFC6238AppendixB_withSkew1(t *testing.T) {
	mod := newTOTP(t, Config{SkewSteps: Int(1)})
	for _, v := range rfcVectors {
		t.Run(v.name, func(t *testing.T) {
			mod.clock = clock.Fixed(time.Unix(v.time, 0).UTC())
			if _, err := mod.VerifyStep(rfcSecretB32, v.code6, 0); err != nil {
				t.Fatalf("Verify with skew=1 at t=%d returned err=%v, want nil",
					v.time, err)
			}
		})
	}
}

// ---- Skew window ------------------------------------------------------------

// TestVerify_SkewSteps1_AcceptsNeighbours exercises the window: with
// SkewSteps=1, codes from the previous and next step are accepted but
// a code from two steps away is not.
func TestVerify_SkewSteps1_AcceptsNeighbours(t *testing.T) {
	mod := newTOTP(t, Config{SkewSteps: Int(1)})
	const baseTime int64 = 60 // any 30-second boundary
	// Compute the TOTP code at baseTime directly via the package helper
	// so the test is deterministic without hardcoding a value.
	key, err := decodeSecret(rfcSecretB32)
	if err != nil {
		t.Fatalf("decodeSecret: %v", err)
	}
	code := generateTOTP(key, uint64(baseTime)/timeStep)

	mod.clock = clock.Fixed(time.Unix(baseTime, 0).UTC())
	current, err := mod.VerifyStep(rfcSecretB32, code, 0)
	if err != nil {
		t.Fatalf("current step should verify: %v", err)
	}
	if current != uint64(baseTime)/timeStep {
		t.Fatalf("current step = %d, want %d", current, uint64(baseTime)/timeStep)
	}

	// The same code must verify at baseTime-30 and baseTime+30.
	mod.clock = clock.Fixed(time.Unix(baseTime-30, 0).UTC())
	if _, err := mod.VerifyStep(rfcSecretB32, code, 0); err != nil {
		t.Errorf("code from previous step should verify with SkewSteps=1: %v", err)
	}
	mod.clock = clock.Fixed(time.Unix(baseTime+30, 0).UTC())
	if _, err := mod.VerifyStep(rfcSecretB32, code, 0); err != nil {
		t.Errorf("code from next step should verify with SkewSteps=1: %v", err)
	}

	// Two steps away must be rejected.
	mod.clock = clock.Fixed(time.Unix(baseTime-60, 0).UTC())
	if _, err := mod.VerifyStep(rfcSecretB32, code, 0); !errors.Is(err, ErrInvalidCode) {
		t.Errorf("code from two steps away: got %v, want ErrInvalidCode", err)
	}
	mod.clock = clock.Fixed(time.Unix(baseTime+60, 0).UTC())
	if _, err := mod.VerifyStep(rfcSecretB32, code, 0); !errors.Is(err, ErrInvalidCode) {
		t.Errorf("code from two steps away: got %v, want ErrInvalidCode", err)
	}
}

// TestVerify_SkewSteps0_OnlyCurrentStep exercises the strictest window:
// with SkewSteps=0, only the current step matches; neighbouring steps
// are rejected.
func TestVerify_SkewSteps0_OnlyCurrentStep(t *testing.T) {
	mod := newTOTP(t, Config{SkewSteps: Int(0)})
	const baseTime int64 = 90
	key, err := decodeSecret(rfcSecretB32)
	if err != nil {
		t.Fatalf("decodeSecret: %v", err)
	}
	code := generateTOTP(key, uint64(baseTime)/timeStep)
	t.Logf("baseTime=%d step=%d code=%s", baseTime, uint64(baseTime)/timeStep, code)

	mod.clock = clock.Fixed(time.Unix(baseTime, 0).UTC())
	current, err := mod.VerifyStep(rfcSecretB32, code, 0)
	if err != nil {
		t.Fatalf("current step should verify with SkewSteps=0: %v", err)
	}
	if current != uint64(baseTime)/timeStep {
		t.Fatalf("current step = %d, want %d", current, uint64(baseTime)/timeStep)
	}

	mod.clock = clock.Fixed(time.Unix(baseTime-30, 0).UTC())
	got := mod.clock.Now().Unix()
	t.Logf("clock set to %d, now=%d, currentStep=%d, code=%s, codeAtStep=%s",
		baseTime-30, got, got/timeStep, code, generateTOTP(key, uint64(got)/timeStep))
	if _, err := mod.VerifyStep(rfcSecretB32, code, 0); !errors.Is(err, ErrInvalidCode) {
		t.Errorf("previous step with SkewSteps=0: got %v, want ErrInvalidCode", err)
	}
	mod.clock = clock.Fixed(time.Unix(baseTime+30, 0).UTC())
	if _, err := mod.VerifyStep(rfcSecretB32, code, 0); !errors.Is(err, ErrInvalidCode) {
		t.Errorf("next step with SkewSteps=0: got %v, want ErrInvalidCode", err)
	}
}

// ---- Replay protection ------------------------------------------------------

func TestVerify_ReplayReturnsErrCodeReused(t *testing.T) {
	mod := newTOTP(t, Config{SkewSteps: Int(0)})
	const baseTime int64 = 120
	key, err := decodeSecret(rfcSecretB32)
	if err != nil {
		t.Fatalf("decodeSecret: %v", err)
	}
	code := generateTOTP(key, uint64(baseTime)/timeStep)

	mod.clock = clock.Fixed(time.Unix(baseTime, 0).UTC())
	step, err := mod.VerifyStep(rfcSecretB32, code, 0)
	if err != nil {
		t.Fatalf("first verify: %v", err)
	}
	if step != uint64(baseTime)/timeStep {
		t.Fatalf("step = %d, want %d", step, uint64(baseTime)/timeStep)
	}

	// Replay the same code with the returned step as lastUsedStep.
	if _, err := mod.VerifyStep(rfcSecretB32, code, step); !errors.Is(err, ErrCodeReused) {
		t.Errorf("replayed code: got %v, want ErrCodeReused", err)
	}

	// lastUsedStep equal to the matched step also triggers it.
	if _, err := mod.VerifyStep(rfcSecretB32, code, step); !errors.Is(err, ErrCodeReused) {
		t.Errorf("replayed code with equal lastUsedStep: got %v, want ErrCodeReused", err)
	}
}

func TestVerify_ReplayAcrossNeighbouringSteps(t *testing.T) {
	// A code for step N is also valid (with SkewSteps >= 1) at any clock
	// time whose current step is in [N-1, N+1]. Once we have accepted it,
	// any subsequent accept at a neighbouring step must also report
	// ErrCodeReused because the matched step is at or below lastUsedStep.
	mod := newTOTP(t, Config{SkewSteps: Int(1)})
	const baseTime int64 = 150
	key, err := decodeSecret(rfcSecretB32)
	if err != nil {
		t.Fatalf("decodeSecret: %v", err)
	}
	code := generateTOTP(key, uint64(baseTime)/timeStep)

	mod.clock = clock.Fixed(time.Unix(baseTime, 0).UTC())
	step, err := mod.VerifyStep(rfcSecretB32, code, 0)
	if err != nil {
		t.Fatalf("first verify at t=%d: %v", baseTime, err)
	}

	mod.clock = clock.Fixed(time.Unix(baseTime+30, 0).UTC())
	if _, err := mod.VerifyStep(rfcSecretB32, code, step); !errors.Is(err, ErrCodeReused) {
		t.Errorf("replayed code from neighbour step: got %v, want ErrCodeReused", err)
	}
}

func TestVerifyStep_ZeroLastUsedStepDisablesReplayRefusal(t *testing.T) {
	// This pins a documented hazard of the low-level primitive: a caller
	// who always passes 0 gets no replay refusal at all. Every matching
	// code is accepted, including codes the user has already used. That
	// is the reason Verify requires a StepRecorder and refuses a nil
	// one with ErrStepRecorderRequired, so the unprotected call site is
	// a programming error rather than a silent footgun.
	mod := newTOTP(t, Config{SkewSteps: Int(0)})
	const baseTime int64 = 210
	key, err := decodeSecret(rfcSecretB32)
	if err != nil {
		t.Fatalf("decodeSecret: %v", err)
	}
	code := generateTOTP(key, uint64(baseTime)/timeStep)
	mod.clock = clock.Fixed(time.Unix(baseTime, 0).UTC())
	for i := 0; i < 5; i++ {
		if _, err := mod.VerifyStep(rfcSecretB32, code, 0); err != nil {
			t.Fatalf("verify #%d with lastUsedStep=0 returned %v, want nil", i, err)
		}
	}
}

// ---- Malformed inputs -------------------------------------------------------

func TestVerify_MalformedCode(t *testing.T) {
	mod := newTOTP(t)
	const baseTime int64 = 30
	mod.clock = clock.Fixed(time.Unix(baseTime, 0).UTC())
	cases := []struct {
		name string
		code string
	}{
		{"empty", ""},
		{"five digits", "12345"},
		{"seven digits", "1234567"},
		{"letter", "12345a"},
		{"symbol", "12345!"},
		{"unicode digit", "１２３４５６"}, // six fullwidth digits
		{"trailing space", "123456 "},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := mod.VerifyStep(rfcSecretB32, c.code, 0)
			if !errors.Is(err, ErrMalformedCode) {
				t.Errorf("Verify(%q) = %v, want ErrMalformedCode", c.code, err)
			}
		})
	}
}

func TestVerify_InvalidSecret(t *testing.T) {
	mod := newTOTP(t, Config{SkewSteps: Int(0)})
	mod.clock = clock.Fixed(epoch)
	cases := []string{
		"",
		"not-base32!",
		"@@@@",
		"1", // valid base32 but too short
	}
	for _, c := range cases {
		t.Run(c, func(t *testing.T) {
			if _, err := mod.VerifyStep(c, "123456", 0); !errors.Is(err, ErrInvalidSecret) {
				t.Errorf("Verify(secret=%q) = %v, want ErrInvalidSecret", c, err)
			}
		})
	}
}
