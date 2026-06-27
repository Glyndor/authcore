package username

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

func newMod(t *testing.T) *Username {
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
	if got := newMod(t).Name(); got != "username" {
		t.Errorf("Name() = %q, want %q", got, "username")
	}
}

// ---- normalize() — internal -------------------------------------------------

func TestNormalize_lowercases(t *testing.T) {
	if got := normalize("Alice123"); got != "alice123" {
		t.Errorf("got %q", got)
	}
}

func TestNormalize_trimsSpaces(t *testing.T) {
	if got := normalize("  alice  "); got != "alice" {
		t.Errorf("got %q", got)
	}
}

func TestNormalize_mixedCaseAndSpaces(t *testing.T) {
	if got := normalize("  ALiCe_123  "); got != "alice_123" {
		t.Errorf("got %q", got)
	}
}

// ---- ValidateAndNormalize() — valid usernames -------------------------------

func TestValidateAndNormalize_normalizes(t *testing.T) {
	m := newMod(t)
	got, err := m.ValidateAndNormalize("  Alice123  ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "alice123" {
		t.Errorf("got %q, want %q", got, "alice123")
	}
}

func TestValidateAndNormalize_valid(t *testing.T) {
	m := newMod(t)
	cases := []string{
		"alice",
		"alice123",
		"alice-bob",
		"alice_bob",
		"a1b2c3",
		"abc", // exactly minLength (3)
		"a-b", // hyphen in middle
		"a_b", // underscore in middle
		"user123name",
		strings.Repeat("a", maxLength), // exactly maxLength (32)
	}
	for _, tc := range cases {
		if _, err := m.ValidateAndNormalize(tc); err != nil {
			t.Errorf("ValidateAndNormalize(%q) = %v, want nil", tc, err)
		}
	}
}

// ---- ValidateAndNormalize() — invalid usernames -----------------------------

func TestValidateAndNormalize_empty(t *testing.T) {
	_, err := newMod(t).ValidateAndNormalize("")
	if !errors.Is(err, ErrInvalidUsername) {
		t.Errorf("expected ErrInvalidUsername, got %v", err)
	}
}

func TestValidateAndNormalize_tooShort(t *testing.T) {
	_, err := newMod(t).ValidateAndNormalize("ab") // 2 chars, min is 3
	if !errors.Is(err, ErrInvalidUsername) {
		t.Errorf("expected ErrInvalidUsername for too-short username, got %v", err)
	}
}

func TestValidateAndNormalize_tooLong(t *testing.T) {
	long := strings.Repeat("a", maxLength+1) // 33 chars, max is 32
	_, err := newMod(t).ValidateAndNormalize(long)
	if !errors.Is(err, ErrInvalidUsername) {
		t.Errorf("expected ErrInvalidUsername for too-long username, got %v", err)
	}
}

func TestValidateAndNormalize_startsWithUnderscore(t *testing.T) {
	_, err := newMod(t).ValidateAndNormalize("_alice")
	if !errors.Is(err, ErrInvalidUsername) {
		t.Errorf("expected ErrInvalidUsername for leading underscore, got %v", err)
	}
}

func TestValidateAndNormalize_startsWithHyphen(t *testing.T) {
	_, err := newMod(t).ValidateAndNormalize("-alice")
	if !errors.Is(err, ErrInvalidUsername) {
		t.Errorf("expected ErrInvalidUsername for leading hyphen, got %v", err)
	}
}

func TestValidateAndNormalize_endsWithUnderscore(t *testing.T) {
	_, err := newMod(t).ValidateAndNormalize("alice_")
	if !errors.Is(err, ErrInvalidUsername) {
		t.Errorf("expected ErrInvalidUsername for trailing underscore, got %v", err)
	}
}

func TestValidateAndNormalize_endsWithHyphen(t *testing.T) {
	_, err := newMod(t).ValidateAndNormalize("alice-")
	if !errors.Is(err, ErrInvalidUsername) {
		t.Errorf("expected ErrInvalidUsername for trailing hyphen, got %v", err)
	}
}

func TestValidateAndNormalize_consecutiveUnderscores(t *testing.T) {
	_, err := newMod(t).ValidateAndNormalize("alice__bob")
	if !errors.Is(err, ErrInvalidUsername) {
		t.Errorf("expected ErrInvalidUsername for consecutive underscores, got %v", err)
	}
}

func TestValidateAndNormalize_consecutiveHyphens(t *testing.T) {
	_, err := newMod(t).ValidateAndNormalize("alice--bob")
	if !errors.Is(err, ErrInvalidUsername) {
		t.Errorf("expected ErrInvalidUsername for consecutive hyphens, got %v", err)
	}
}

func TestValidateAndNormalize_mixedConsecutiveSpecials(t *testing.T) {
	cases := []string{
		"alice_-bob",
		"alice-_bob",
	}
	m := newMod(t)
	for _, tc := range cases {
		if _, err := m.ValidateAndNormalize(tc); !errors.Is(err, ErrInvalidUsername) {
			t.Errorf("ValidateAndNormalize(%q): expected ErrInvalidUsername, got %v", tc, err)
		}
	}
}

func TestValidateAndNormalize_invalidCharacters(t *testing.T) {
	cases := []string{
		"alice@example",
		"alice.bob",
		"alice bob",
		"alice!",
		"üser",
	}
	m := newMod(t)
	for _, tc := range cases {
		if _, err := m.ValidateAndNormalize(tc); !errors.Is(err, ErrInvalidUsername) {
			t.Errorf("ValidateAndNormalize(%q): expected ErrInvalidUsername, got %v", tc, err)
		}
	}
}

// ---- Reserved names ---------------------------------------------------------

func TestValidateAndNormalize_reservedName(t *testing.T) {
	m := newMod(t)
	for _, reserved := range defaultReservedNames {
		if _, err := m.ValidateAndNormalize(reserved); !errors.Is(err, ErrInvalidUsername) {
			t.Errorf("ValidateAndNormalize(%q): expected ErrInvalidUsername for reserved name, got %v", reserved, err)
		}
	}
}

func TestValidateAndNormalize_reservedNameCaseInsensitive(t *testing.T) {
	m := newMod(t)
	// "ADMIN" normalizes to "admin" which is reserved.
	if _, err := m.ValidateAndNormalize("ADMIN"); !errors.Is(err, ErrInvalidUsername) {
		t.Errorf("expected ErrInvalidUsername for reserved name 'ADMIN', got %v", err)
	}
}

// ---- ErrInvalidUsername wraps a reason --------------------------------------

func TestValidateAndNormalize_wrapsReason(t *testing.T) {
	_, err := newMod(t).ValidateAndNormalize("")
	if !errors.Is(err, ErrInvalidUsername) {
		t.Fatalf("expected ErrInvalidUsername, got %v", err)
	}
	reason := errors.Unwrap(err)
	if reason == nil {
		t.Fatal("expected wrapped reason, got nil")
	}
	if reason.Error() == "" {
		t.Error("wrapped reason must not be empty")
	}
}
