package password

import (
	"errors"
	"strings"
	"testing"

	"github.com/Glyndor/authcore"
)

// New refuses a nil provider or logger and a second Config (2026-09-25):
// the first two panicked and the third was dropped without a word.

type nilLoggerProvider struct{ fakeProvider }

func (nilLoggerProvider) Logger() authcore.Logger { return nil }

func TestNew_refusesWhatItCannotUse(t *testing.T) {
	for name, tc := range map[string]struct {
		build func() (*Password, error)
		want  string
	}{
		"nil provider": {func() (*Password, error) { return New(nil) }, "provider is nil"},
		"nil logger":   {func() (*Password, error) { return New(nilLoggerProvider{}) }, "Logger() returned nil"},
		"two configs":  {func() (*Password, error) { return New(fakeProvider{}, Config{}, Config{}) }, "at most one Config"},
	} {
		_, err := tc.build()
		if !errors.Is(err, ErrInvalidConfig) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want ErrInvalidConfig naming %q", name, err, tc.want)
		}
	}
	if _, err := New(fakeProvider{}, Config{}); err != nil {
		t.Fatalf("one Config: %v, want accepted", err)
	}
}

// New snapshots each *bool policy field, so flipping the caller's value after
// New changes nothing. #437 pinned RequireSymbol only; three lines of four
// could go.
func TestNew_snapshotsEveryPolicyPointer(t *testing.T) {
	for name, tc := range map[string]struct {
		field    func(*Config) **bool
		password string // fails exactly that requirement
	}{
		"RequireUpper":  {func(c *Config) **bool { return &c.RequireUpper }, "abcdefghijk1!"},
		"RequireLower":  {func(c *Config) **bool { return &c.RequireLower }, "ABCDEFGHIJK1!"},
		"RequireDigit":  {func(c *Config) **bool { return &c.RequireDigit }, "Abcdefghijkl!"},
		"RequireSymbol": {func(c *Config) **bool { return &c.RequireSymbol }, "Abcdefghijk12"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := DefaultConfig()
			on := true
			*tc.field(&cfg) = &on
			mod, err := New(fakeProvider{}, cfg)
			if err != nil {
				t.Fatal(err)
			}
			if err := mod.ValidatePolicy(tc.password); !errors.Is(err, ErrWeakPassword) {
				t.Fatalf("before the flip, ValidatePolicy(%q) = %v, want ErrWeakPassword", tc.password, err)
			}
			on = false // the caller's variable, which the module must not read
			if err := mod.ValidatePolicy(tc.password); !errors.Is(err, ErrWeakPassword) {
				t.Fatalf("after flipping the caller's %s, ValidatePolicy(%q) = %v, want still refused", name, tc.password, err)
			}
		})
	}
}

// The work-factor ceilings at New: a value past them is refused, one at
// them is accepted. Only the parse-time ceilings had tests.
func TestNew_refusesWorkFactorsPastTheCeilings(t *testing.T) {
	for name, tc := range map[string]struct {
		cfg    Config
		reason string
	}{
		"memory past the ceiling":     {Config{Memory: maxMemory + 1, Iterations: 1, Parallelism: 1}, "memory must be at most"},
		"iterations past the ceiling": {Config{Memory: minMemory, Iterations: maxIterations + 1, Parallelism: 1}, "iterations must be at most"},
	} {
		_, err := New(fakeProvider{}, tc.cfg)
		if !errors.Is(err, ErrInvalidConfig) || !strings.Contains(err.Error(), tc.reason) {
			t.Errorf("%s: %v, want ErrInvalidConfig naming %q", name, err, tc.reason)
		}
	}
	if _, err := New(fakeProvider{}, Config{Memory: minMemory, Iterations: maxIterations, Parallelism: 1}); err != nil {
		t.Fatalf("iterations at the ceiling: %v, want accepted", err)
	}
}
