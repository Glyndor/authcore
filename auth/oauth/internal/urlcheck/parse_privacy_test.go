package urlcheck_test

import (
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth/internal/urlcheck"
)

func TestRequireHTTPSParseErrorsNeverRepeatURLCredentials(t *testing.T) {
	t.Parallel()
	const user, secret = "user-canary-4107", "password-canary-5209"
	for _, suffix := range []string{"/%zz", ":bad/token", "/\x7f"} {
		raw := "https://" + user + ":" + secret + "@provider.example" + suffix
		err := urlcheck.RequireHTTPS("token_endpoint", raw)
		if err == nil {
			t.Fatalf("malformed URL suffix %q was accepted", suffix)
		}
		for _, credential := range []string{user, secret} {
			if strings.Contains(err.Error(), credential) {
				t.Fatalf("URL parser diagnostic repeated a credential for suffix %q", suffix)
			}
		}
	}
	if err := urlcheck.RequireHTTPS("token_endpoint", "https://provider.example/token"); err != nil {
		t.Fatalf("valid URL refused: %v", err)
	}
}
