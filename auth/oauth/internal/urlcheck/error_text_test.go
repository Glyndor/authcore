package urlcheck_test

import (
	"errors"
	"strings"
	"testing"
	"unicode"

	"github.com/Glyndor/authcore/auth/oauth/internal/urlcheck"
)

func TestRequireHTTPSBoundsRemotePortParserErrors(t *testing.T) {
	t.Parallel()
	const canary = "REMOTE_PORT_CANARY"
	raw := "https://p.example:" + strings.Repeat("7", 65000) + canary
	err := urlcheck.RequireHTTPS("token_endpoint", raw)
	if err == nil {
		t.Fatal("invalid port accepted")
	}
	for cause := err; cause != nil; cause = errors.Unwrap(cause) {
		if len(cause.Error()) > 1024 || strings.Contains(cause.Error(), canary) {
			t.Fatalf("parser diagnostic retains remote port: %d bytes", len(cause.Error()))
		}
		for _, r := range cause.Error() {
			if !unicode.IsPrint(r) {
				t.Fatalf("nonprintable diagnostic rune %U", r)
			}
		}
	}
	if err := urlcheck.RequireHTTPS("token_endpoint", "https://p.example:443/token"); err != nil {
		t.Fatal(err)
	}
}
