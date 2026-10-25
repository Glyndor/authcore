package discovery

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// ErrDiscovery stands in for the public oauth.ErrDiscovery sentinel, which the
// oauth package passes to Fetch.
var ErrDiscovery = errors.New("oauth: OIDC discovery failed")

// TestFetchGuardsSuppliedClient requires a trusted HTTPS discovery fetch to
// refuse a plaintext redirect and wrap that refusal in ErrDiscovery.
func TestFetchGuardsSuppliedClient(t *testing.T) {
	t.Parallel()
	// target serves a valid document if an unguarded client follows the redirect.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := fmt.Fprintf(w, `{
			"issuer": %q,
			"authorization_endpoint": "https://provider.example/auth",
			"token_endpoint": "https://provider.example/token",
			"jwks_uri": "https://provider.example/jwks"
		}`, r.URL.Query().Get("issuer")); err != nil {
			t.Errorf("write discovery document: %v", err)
		}
	}))
	defer target.Close()
	// server downgrades the discovery request to the plaintext document target.
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != discoveryPath {
			http.NotFound(w, r)
			return
		}
		http.Redirect(
			w,
			r,
			target.URL+"?issuer="+url.QueryEscape("https://"+r.Host),
			http.StatusTemporaryRedirect,
		)
	}))
	defer server.Close()
	// caller trusts the TLS fixture and supplies no redirect callback.
	caller := *server.Client()
	caller.CheckRedirect = nil
	caller.Timeout = 3 * time.Second
	// err must retain both the discovery sentinel and the downgrade refusal.
	_, err := Fetch(t.Context(), server.URL, &caller, ErrDiscovery)
	if !errors.Is(err, ErrDiscovery) {
		t.Fatalf("Fetch = %v, want ErrDiscovery", err)
	}
	if !strings.Contains(err.Error(), "refusing redirect to non-https") {
		t.Fatalf("Fetch refused for the wrong reason: %v", err)
	}
}
