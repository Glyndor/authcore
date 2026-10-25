package normalize_test

import (
	"testing"

	"github.com/Glyndor/authcore/auth/email/internal/normalize"
)

// ---- normalize() — internal -------------------------------------------------

func TestNormalize_lowercases(t *testing.T) {
	got, err := normalize.Address("USER@EXAMPLE.COM")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "user@example.com" {
		t.Errorf("got %q", got)
	}
}

func TestNormalize_trimsSpaces(t *testing.T) {
	got, err := normalize.Address("  user@example.com  ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "user@example.com" {
		t.Errorf("got %q", got)
	}
}

func TestNormalize_mixedCaseAndSpaces(t *testing.T) {
	got, err := normalize.Address("  Ana@Example.COM  ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "ana@example.com" {
		t.Errorf("got %q", got)
	}
}
