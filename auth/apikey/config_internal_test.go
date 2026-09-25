package apikey

import (
	"strings"
	"testing"
)

// validateConfig refuses an empty prefix on its own, although New fills one
// in before calling it (see the comment there). Deleting the check leaves
// every test that goes through New green, so this one calls it directly.
func TestValidateConfig_refusesAnEmptyPrefix(t *testing.T) {
	err := validateConfig(Config{})
	if err == nil || !strings.Contains(err.Error(), "prefix must not be empty") {
		t.Fatalf("validateConfig(Config{}) = %v, want the empty-prefix refusal", err)
	}
	if err := validateConfig(Config{Prefix: "a"}); err != nil {
		t.Fatalf("validateConfig with a one-character prefix = %v, want nil", err)
	}
}
