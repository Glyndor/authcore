package totp

import (
	"errors"
	"strings"
	"testing"

	"github.com/Glyndor/authcore"
)

type nilLoggerProvider struct{ fakeProvider }

func (nilLoggerProvider) Logger() authcore.Logger { return nil }

// New refuses what it cannot use (2026-09-25): a nil provider, logger or
// Keys panicked, a short refresh secret keyed recovery-code hashes with a
// value anyone can compute, and a second Config was dropped.
func TestNew_refusesWhatItCannotUse(t *testing.T) {
	short := fakeProvider{keys: fakeKeys{secret: make([]byte, 16)}}
	for name, tc := range map[string]struct {
		build func() (*TOTP, error)
		want  string
	}{
		"nil provider": {func() (*TOTP, error) { return New(nil) }, "provider is nil"},
		"nil logger":   {func() (*TOTP, error) { return New(nilLoggerProvider{newFakeProvider(t)}) }, "Logger() returned nil"},
		"nil keys":     {func() (*TOTP, error) { return New(fakeProvider{}) }, "Keys() returned nil"},
		"short secret": {func() (*TOTP, error) { return New(short) }, "refresh secret has wrong length: got 16"},
		"two configs":  {func() (*TOTP, error) { return New(newFakeProvider(t), Config{}, Config{}) }, "at most one Config"},
	} {
		_, err := tc.build()
		if !errors.Is(err, ErrInvalidConfig) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want ErrInvalidConfig naming %q", name, err, tc.want)
		}
	}
	if _, err := New(newFakeProvider(t), Config{}); err != nil {
		t.Fatalf("a real provider and one Config: %v", err)
	}
}

// Writing through the caller's SkewSteps pointer after New must not widen
// the window of the built module: at 1,000,000 four of five arbitrary codes
// verified before New copied the value.
func TestNew_copiesSkewSteps(t *testing.T) {
	cfg := Config{SkewSteps: Int(1)}
	mod := newTOTP(t, cfg)
	enr, err := mod.Enroll("alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	key, err := decodeSecret(enr.Secret)
	if err != nil {
		t.Fatal(err)
	}
	now := uint64(epoch.Unix()) / timeStep
	old := generateTOTP(key, now-120) // an hour ago

	*cfg.SkewSteps = 1_000_000
	if _, err := mod.VerifyStep(enr.Secret, old, 0); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("an hour-old code after the caller widened its int: %v, want ErrInvalidCode", err)
	}
	if _, err := mod.VerifyStep(enr.Secret, generateTOTP(key, now), 0); err != nil {
		t.Fatalf("the current code: %v, want accepted", err)
	}
}

// A secret has one spelling: the base32 decoder skips line breaks.
func TestDecodeSecret_refusesLineBreaks(t *testing.T) {
	enr, err := newTOTP(t).Enroll("alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeSecret(enr.Secret); err != nil {
		t.Fatalf("the secret as enrolled: %v", err)
	}
	for _, s := range []string{enr.Secret[:8] + "\n" + enr.Secret[8:], enr.Secret[:16] + "\r\n" + enr.Secret[16:]} {
		if _, err := decodeSecret(s); !errors.Is(err, ErrInvalidSecret) {
			t.Errorf("%q: %v, want ErrInvalidSecret", s, err)
		}
	}
}
