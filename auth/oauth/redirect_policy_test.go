package oauth

import (
	"net/http"
	"testing"
	"time"
)

// TestSuppliedClientKeepsTheRedirectGuards is the regression for the case where
// a caller-supplied client arrived with CheckRedirect nil, which silently
// removed the hop cap, the https requirement, the private-host SSRF guard and
// the cross-origin guard from every fetch this package makes.
func TestSuppliedClientKeepsTheRedirectGuards(t *testing.T) {
	own := &http.Client{Timeout: 3 * time.Second}
	cfg := applyDefaults(Config{HTTPClient: own})

	if cfg.HTTPClient.CheckRedirect == nil {
		t.Fatal("a caller-supplied client came back with no redirect policy")
	}
	if cfg.HTTPClient.Timeout != 3*time.Second {
		t.Errorf("the caller's timeout was discarded: got %v, want 3s", cfg.HTTPClient.Timeout)
	}
}

// TestTheCallersOwnClientIsNotMutated pins the other half of the fix. Forcing
// the policy onto the caller's client would change how it behaves everywhere
// else in their program, so the package works on a copy.
func TestTheCallersOwnClientIsNotMutated(t *testing.T) {
	own := &http.Client{Timeout: 3 * time.Second}
	cfg := applyDefaults(Config{HTTPClient: own})

	if own.CheckRedirect != nil {
		t.Error("the caller's own client was mutated")
	}
	if cfg.HTTPClient == own {
		t.Error("the package kept the caller's client rather than a copy")
	}
}

// TestDefaultClientStillCarriesThePolicy guards the path that was already
// correct, so a refactor cannot fix one case by breaking the other.
func TestDefaultClientStillCarriesThePolicy(t *testing.T) {
	if applyDefaults(Config{}).HTTPClient.CheckRedirect == nil {
		t.Error("the default client has no redirect policy")
	}
}

// TestLoopbackExceptionCoversTheWholeRange covers the plaintext exception.
// Only loopback may be http; everything else must still be refused.
func TestLoopbackExceptionCoversTheWholeRange(t *testing.T) {
	for host, want := range map[string]bool{
		"localhost":          true,
		"127.0.0.1":          true,
		"127.0.0.2":          true,
		"127.1.2.3":          true,
		"::1":                true,
		"10.0.0.1":           false,
		"192.168.1.1":        false,
		"example.com":        false,
		"localhost.evil.com": false,
		"":                   false,
	} {
		if got := isLoopbackHost(host); got != want {
			t.Errorf("isLoopbackHost(%q) = %v, want %v", host, got, want)
		}
	}
}
