package oauth

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/Glyndor/authcore"
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

func (appleFakeProvider) Config() authcore.Config { return authcore.DefaultConfig() }
func (appleFakeProvider) Logger() authcore.Logger { return silentLogger{} }
func (appleFakeProvider) Keys() authcore.Keys     { return nil }

func (silentLogger) Debug(string, ...any) {}
func (silentLogger) Info(string, ...any)  {}
func (silentLogger) Warn(string, ...any)  {}
func (silentLogger) Error(string, ...any) {}

const appleTestClientID = "com.example.services"

// TestAppleDefaultScopes_AreCloned pins that applyDefaults clones the
// Provider.DefaultScopes slice. A caller that mutates the slice on the
// Provider they handed in must NOT change what a built client later
// sends. Without the clone, the test's tampered slice would surface in
// the URL on the second AuthCodeURL.
func TestAppleDefaultScopes_AreCloned(t *testing.T) {
	t.Parallel()
	p := Apple()
	c, err := New(appleFakeProvider{}, Config{
		ClientID:    appleTestClientID,
		RedirectURL: "https://app.example.com/auth/apple/callback",
		Provider: Provider{
			Issuer:        p.Issuer,
			AuthURL:       p.AuthURL,
			TokenURL:      p.TokenURL,
			JWKSURL:       p.JWKSURL,
			AuthMethods:   p.AuthMethods,
			DefaultScopes: p.DefaultScopes,
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	cfg := c.cfg.Provider
	cfg.DefaultScopes[0] = "tampered"
	req, _ := c.AuthCodeURL()
	u, _ := url.Parse(req.URL)
	if got := u.Query().Get("scope"); got != "openid email name" {
		t.Errorf("scope = %q, want %q (the built client's slice must be independent of the caller's)", got, "openid email name")
	}
}

// appleFakeProvider supplies authcore.Provider values to oauth.New during
// tests. It mirrors the test provider in package oauth_test, which is not
// importable here.
type appleFakeProvider struct{}

// silentLogger satisfies authcore.Logger with no output. The library uses
// it on the success path only; this package's tests assert via errors.
type silentLogger struct{}
