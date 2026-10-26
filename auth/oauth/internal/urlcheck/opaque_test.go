package urlcheck_test

import (
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth/internal/urlcheck"
)

// An opaque URL is named as such, not reported as merely lacking a host.
func TestRequireHTTPSNamesAnOpaqueURL(t *testing.T) {
	t.Parallel()
	err := urlcheck.RequireHTTPS("provider auth URL", "https:idp.example/auth")
	if err == nil || !strings.Contains(err.Error(), "opaque") {
		t.Fatalf("err = %v, want a refusal that says the URL is opaque", err)
	}
}
