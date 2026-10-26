package email

import (
	"errors"
	"strings"
	"testing"

	"github.com/Glyndor/authcore"
)

// ---- test helpers -----------------------------------------------------------

type fakeProvider struct{}

func (fakeProvider) Config() authcore.Config { return authcore.DefaultConfig() }
func (fakeProvider) Logger() authcore.Logger { return silentLogger{} }
func (fakeProvider) Keys() authcore.Keys     { return nil }

type silentLogger struct{}

func (silentLogger) Debug(string, ...any) {}
func (silentLogger) Info(string, ...any)  {}
func (silentLogger) Warn(string, ...any)  {}
func (silentLogger) Error(string, ...any) {}

func newMod(t *testing.T) *Email {
	t.Helper()
	m, err := New(fakeProvider{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return m
}

// ---- New() ------------------------------------------------------------------

func TestNew_succeeds(t *testing.T) {
	if _, err := New(fakeProvider{}); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}

func TestName(t *testing.T) {
	if got := newMod(t).Name(); got != "email" {
		t.Errorf("Name() = %q, want %q", got, "email")
	}
}

// ---- New(p) reproduces today's behaviour ------------------------------------

func TestNew_acceptsPlusAddressing(t *testing.T) {
	// The zero Config{} - which is what New(p) uses - must NOT reject
	// plus-addressing, because that is the existing behaviour callers
	// depend on. Today the module is built with New(p); the change here is
	// purely additive.
	m := newMod(t)
	if _, err := m.ValidateAndNormalize("user+tag@example.com"); err != nil {
		t.Errorf("New(p) must accept plus-addressing by default, got %v", err)
	}
}

// ---- NewWithConfig(p, Config{RejectPlusAddressing: true}) --------------------

func TestNewWithConfig_rejectsPlusAddressing(t *testing.T) {
	mod, err := NewWithConfig(fakeProvider{}, Config{RejectPlusAddressing: true})
	if err != nil {
		t.Fatalf("NewWithConfig: %v", err)
	}

	_, err = mod.ValidateAndNormalize("user+tag@example.com")
	if !errors.Is(err, ErrInvalidEmail) {
		t.Fatalf("expected ErrInvalidEmail for plus-addressing, got %v", err)
	}
	if reason := errors.Unwrap(err); reason == nil || !strings.Contains(reason.Error(), "plus") {
		t.Errorf("error reason must name the rule (plus-addressing), got %v", reason)
	}
}

func TestNewWithConfig_rejectPlusStillPassesNormalAddresses(t *testing.T) {
	// Turning plus-addressing rejection ON must not affect addresses that
	// do not contain '+'. The whole point of the toggle is the
	// plus-addressing rule specifically, not a stricter structural check.
	mod, err := NewWithConfig(fakeProvider{}, Config{RejectPlusAddressing: true})
	if err != nil {
		t.Fatalf("NewWithConfig: %v", err)
	}

	for _, addr := range []string{
		"user@example.com",
		"user.name@example.com",
		"a@b.io",
	} {
		if _, err := mod.ValidateAndNormalize(addr); err != nil {
			t.Errorf("ValidateAndNormalize(%q) = %v, want nil", addr, err)
		}
	}
}

func TestNewWithConfig_emptyConfigMatchesNew(t *testing.T) {
	// Calling NewWithConfig with the zero Config{} must reproduce the
	// behaviour of New(p). This is the additive guarantee: New keeps
	// working, and zero-value Config{} in NewWithConfig does the same.
	a, err := NewWithConfig(fakeProvider{}, Config{})
	if err != nil {
		t.Fatalf("NewWithConfig: %v", err)
	}
	b := newMod(t)

	if _, err := a.ValidateAndNormalize("user+tag@example.com"); err != nil {
		t.Errorf("zero Config{} must accept plus-addressing, got %v", err)
	}
	if _, err := b.ValidateAndNormalize("user+tag@example.com"); err != nil {
		t.Errorf("New(p) must accept plus-addressing, got %v", err)
	}
}

// ---- structural errors must surface before plus-addressing ------------------

func TestNewWithConfig_plusAddressWithBadDomainStillReportsDomain(t *testing.T) {
	// If the user passes a structurally invalid address that also contains
	// a '+', they should see the structural error (more actionable), not
	// the policy error. The policy check sits AFTER structural validation.
	mod, err := NewWithConfig(fakeProvider{}, Config{RejectPlusAddressing: true})
	if err != nil {
		t.Fatalf("NewWithConfig: %v", err)
	}

	_, err = mod.ValidateAndNormalize("user+tag@example..com")
	if !errors.Is(err, ErrInvalidEmail) {
		t.Fatalf("expected ErrInvalidEmail, got %v", err)
	}
	reason := errors.Unwrap(err)
	if reason == nil || strings.Contains(reason.Error(), "plus") {
		t.Errorf("structural error must surface first; got %v", reason)
	}
}

type nilLoggerProvider struct{ fakeProvider }

func (nilLoggerProvider) Logger() authcore.Logger { return nil }

// A nil provider or logger panicked until 2026-09-25.
func TestNewWithConfig_refusesANilProviderOrLogger(t *testing.T) {
	if _, err := New(nil); !errors.Is(err, ErrInvalidConfig) || !strings.Contains(err.Error(), "provider is nil") {
		t.Errorf("New(nil) = %v, want ErrInvalidConfig", err)
	}
	if _, err := NewWithConfig(nilLoggerProvider{}, Config{}); !errors.Is(err, ErrInvalidConfig) || !strings.Contains(err.Error(), "Logger() returned nil") {
		t.Errorf("nil logger = %v, want ErrInvalidConfig", err)
	}
}

func TestClose_isIdempotent(t *testing.T) {
	m := newMod(t)
	m.Close()
	m.Close() // must not panic
}

func newBenchEmail(b *testing.B) *Email {
	b.Helper()
	auth, err := authcore.New(authcore.Config{EnableLogs: false, KeysDir: b.TempDir()})
	if err != nil {
		b.Fatal(err)
	}
	mod, err := New(auth)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(mod.Close)
	return mod
}

func BenchmarkValidateAndNormalize(b *testing.B) {
	mod := newBenchEmail(b)
	addr := "User@Example.COM"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := mod.ValidateAndNormalize(addr); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkValidateAndNormalizeInvalid(b *testing.B) {
	mod := newBenchEmail(b)
	addr := "not-an-email"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = mod.ValidateAndNormalize(addr)
	}
}
