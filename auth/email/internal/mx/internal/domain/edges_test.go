package domain_test

import (
	"testing"

	"github.com/Glyndor/authcore/auth/email/internal/mx/internal/domain"
)

func TestOfAndPlausibleAtTheirEdges(t *testing.T) {
	t.Parallel()
	if got := domain.Of("@example.com"); got != "example.com" {
		t.Errorf("Of with an empty local part = %q, want example.com", got)
	}
	if got := domain.Of("no-at-sign"); got != "" {
		t.Errorf("Of without an at sign = %q, want empty", got)
	}
	if !domain.Plausible("a") {
		t.Error("a one-byte domain is within DNS limits")
	}
	if domain.Plausible("") {
		t.Error("an empty domain is not")
	}
}
