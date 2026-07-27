package oauth

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// safeRedirect applies four guards in order — hop count, https, private host,
// same origin — and the first two make the last two unreachable from any test
// that redirects between local servers: an httptest server is plaintext on a
// loopback address, so the scheme and private-host guards fire long before the
// hop count or the origin check can. That is why the end-to-end redirect test
// stays green when either of those is deleted, and why they are exercised here
// against the function directly instead.
func req(t *testing.T, raw string) *http.Request {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return &http.Request{URL: u, Host: u.Host}
}

func TestSafeRedirect(t *testing.T) {
	const origin = "https://provider.example/token"

	for name, tc := range map[string]struct {
		to   string
		hops int
		want string // substring of the expected rejection, "" means allowed
	}{
		"same origin is allowed":         {to: "https://provider.example/token2", want: ""},
		"cross-origin leaks the secret":  {to: "https://evil.example/steal", want: "cross-origin"},
		"plaintext downgrade":            {to: "http://provider.example/token", want: "non-https"},
		"cloud metadata endpoint":        {to: "https://169.254.169.254/latest", want: "private host"},
		"loopback":                       {to: "https://127.0.0.1/token", want: "private host"},
		"private range":                  {to: "https://10.0.0.5/token", want: "private host"},
		"too many hops on the same host": {to: "https://provider.example/token", hops: 5, want: "too many redirects"},
	} {
		t.Run(name, func(t *testing.T) {
			hops := tc.hops
			if hops == 0 {
				hops = 1
			}
			via := make([]*http.Request, hops)
			for i := range via {
				via[i] = req(t, origin)
			}

			err := safeRedirect(req(t, tc.to), via)

			if tc.want == "" {
				if err != nil {
					t.Fatalf("redirect to %q should be allowed, got: %v", tc.to, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("redirect to %q must be refused", tc.to)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("redirect to %q refused for the wrong reason: want %q, got: %v", tc.to, tc.want, err)
			}
		})
	}
}
