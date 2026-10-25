package redirect_test

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/oauth"
	"github.com/Glyndor/authcore/auth/oauth/internal/oauthtest"
)

// TestExchange_refusesUnsafeRedirect requires the redirect policy to refuse a
// token-endpoint redirect that would replay the client secret. The cross-origin
// case points at a local HTTPS server whose URL is rewritten to use the
// "localhost" hostname (a hostname, not an IP literal, so the private-host
// check lets the request through to the cross-origin check). The destination
// handler returns a valid tokens response; if the redirect policy fires,
// Exchange fails; if it does not, Exchange succeeds and the test fails because
// no error was returned. The other cases use URLs that fail at the policy
// stage before any dial. A DNS or dial error used to satisfy the assertion
// without the redirect policy firing.
func TestExchange_refusesUnsafeRedirect(t *testing.T) {
	// destination serves a valid tokens body. The library's http.Client is
	// configured to skip TLS hostname verification (test only) so a removed
	// redirect policy would actually reach the destination, where the
	// handler returns a valid tokens response and Exchange succeeds.
	destination := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":"Bearer"}`))
	}))
	defer destination.Close()

	trustedClient := destination.Client()
	trustedClient.Timeout = 5 * time.Second
	// InsecureSkipVerify is a test-only setting: the destination's cert is
	// for "127.0.0.1" but the redirect URL rewrites the host to "localhost",
	// which the runtime TLS stack would otherwise reject. Production code
	// never runs with this setting.
	if tr, ok := trustedClient.Transport.(*http.Transport); ok {
		if tr.TLSClientConfig == nil {
			tr.TLSClientConfig = &tls.Config{}
		}
		tr.TLSClientConfig.InsecureSkipVerify = true
	}

	// destinationURL rewrites the host to "localhost" so the policy reaches
	// the cross-origin check. The redirect fires before the dial, so TLS
	// verification is the destination's concern, not the policy's.
	destinationURL := strings.Replace(destination.URL, "127.0.0.1", "localhost", 1)

	for name, target := range map[string]string{
		"cross-origin (leaks the secret)": destinationURL,
		"private metadata host (SSRF)":    "https://169.254.169.254/latest",
		"plaintext downgrade":             "http://127.0.0.1/x",
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, target, http.StatusTemporaryRedirect)
			}))
			t.Cleanup(srv.Close)
			c, err := oauth.New(oauthtest.FakeProvider{}, oauth.Config{
				ClientID:    oauthtest.ClientID,
				RedirectURL: "https://app.example/cb",
				Scopes:      []string{"read:user"},
				HTTPClient:  trustedClient,
				Provider: oauth.Provider{
					AuthURL:     srv.URL + "/a",
					TokenURL:    srv.URL + "/token",
					UserInfoURL: srv.URL + "/u",
				},
			})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if _, err := c.Exchange(context.Background(), "code", "verifier"); err == nil {
				t.Errorf("token exchange must refuse the redirect to %q", target)
			}
		})
	}
}

// TestSuppliedClient_zeroTimeoutGetsTheLibraryDefault pins the public-facing
// half of the rule: a caller-supplied client with a zero Timeout is accepted
// at construction and the caller's value is preserved on the original. The
// library's internal copy carries the 10-second default; that branch is
// pinned by TestGuardClient_appliesDefaultTimeoutToZeroTimeoutCaller in the
// internal test, since the internal http.Client is not exposed here.
func TestSuppliedClient_zeroTimeoutGetsTheLibraryDefault(t *testing.T) {
	caller := &http.Client{} // Timeout deliberately zero
	if _, err := oauth.New(oauthtest.FakeProvider{}, oauth.Config{
		ClientID:    oauthtest.ClientID,
		RedirectURL: "https://app.example/cb",
		HTTPClient:  caller,
		Provider:    oauth.Google(),
	}); err != nil {
		t.Fatalf("New: %v", err)
	}
	if caller.Timeout != 0 {
		t.Errorf("the caller's client was mutated: Timeout = %v", caller.Timeout)
	}
}
