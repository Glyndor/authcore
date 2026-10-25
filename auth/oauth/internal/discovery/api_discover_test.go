package discovery_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth"
)

func discoveryServer(t *testing.T, issuer func() string, extra string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration") {
			http.NotFound(w, r)
			return
		}
		fmt.Fprintf(w, `{
			"issuer": %q,
			"authorization_endpoint": "%s/auth",
			"token_endpoint": "%s/token",
			"jwks_uri": "%s/jwks",
			"userinfo_endpoint": "%s/userinfo"
			%s
		}`, issuer(), issuer(), issuer(), issuer(), issuer(), extra)
	}))
}

func TestDiscover_success(t *testing.T) {
	var srv *httptest.Server
	srv = discoveryServer(t, func() string { return srv.URL }, "")
	defer srv.Close()

	p, err := oauth.Discover(context.Background(), srv.URL, nil)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if p.Issuer != srv.URL || p.AuthURL != srv.URL+"/auth" || p.JWKSURL != srv.URL+"/jwks" {
		t.Errorf("unexpected provider: %+v", p)
	}
	if p.UserInfoURL != srv.URL+"/userinfo" {
		t.Errorf("userinfo not discovered: %q", p.UserInfoURL)
	}
}

func TestDiscover_issuerMismatchRejected(t *testing.T) {
	// The document claims a different issuer than the one requested.
	srv := discoveryServer(t, func() string { return "https://evil.example" }, "")
	defer srv.Close()
	if _, err := oauth.Discover(context.Background(), srv.URL, nil); err == nil {
		t.Error("expected rejection on issuer mismatch")
	}
}

func TestDiscover_non200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Return a valid JSON body at the failing status so the rejection
		// must come from the status check, not from decoding an empty body.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"not found"}`))
	}))
	defer srv.Close()
	if _, err := oauth.Discover(context.Background(), srv.URL, nil); err == nil {
		t.Error("expected error on non-200")
	}
}

func TestDiscover_missingEndpoints(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// issuer matches but no endpoints.
		fmt.Fprintf(w, `{"issuer":"http://%s"}`, r.Host)
	}))
	defer srv.Close()
	if _, err := oauth.Discover(context.Background(), "http://"+srv.Listener.Addr().String(), nil); err == nil {
		t.Error("expected error when required endpoints are missing")
	}
}

func TestDiscover_garbage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()
	if _, err := oauth.Discover(context.Background(), srv.URL, nil); err == nil {
		t.Error("expected error on undecodable document")
	}
}

func TestDiscover_non2xxRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()
	_, err := oauth.Discover(context.Background(), srv.URL, nil)
	if !errors.Is(err, oauth.ErrDiscovery) {
		t.Fatalf("expected ErrDiscovery, got %v", err)
	}
	if !strings.Contains(err.Error(), "502") {
		t.Fatalf("error does not name the status (want 502), got %v", err)
	}
	// Acceptance pair: a valid document on a separate server parses and returns
	// the provider. The closure captures goodURL so the discovery response can
	// echo its own URL back as the issuer.
	var goodURL string
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `{"issuer":%q,"authorization_endpoint":%q,"token_endpoint":%q,"jwks_uri":%q}`,
			goodURL, goodURL+"/a", goodURL+"/t", goodURL+"/j")
	}))
	goodURL = good.URL
	defer good.Close()
	if _, err := oauth.Discover(context.Background(), good.URL, nil); err != nil {
		t.Fatalf("acceptance: Discover, got %v", err)
	}
}

func TestDiscover_bodyNotJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`<!DOCTYPE html><html><body>oops</body></html>`))
	}))
	defer srv.Close()
	_, err := oauth.Discover(context.Background(), srv.URL, nil)
	if !errors.Is(err, oauth.ErrDiscovery) {
		t.Fatalf("expected ErrDiscovery, got %v", err)
	}
	if !strings.Contains(err.Error(), "decode") {
		t.Fatalf("error does not name the cause (want decode), got %v", err)
	}
}

func TestDiscover_rejectsNonHTTPSIssuer(t *testing.T) {
	if _, err := oauth.Discover(context.Background(), "http://id.example", nil); err == nil {
		t.Error("expected a non-https issuer to be rejected before any fetch")
	}
}

// TestDiscover_rejectsTrailingSlashIssuer pins the exact-match rule: the
// trimmed form used to be accepted because it was used to build the well-known
// URL. A document that returns the trimmed form is rejected, because it does
// not match the issuer the caller asked for byte-for-byte.
func TestDiscover_rejectsTrailingSlashIssuer(t *testing.T) {
	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration") {
			http.NotFound(w, r)
			return
		}
		fmt.Fprintf(w, `{
			"issuer": %q,
			"authorization_endpoint": %q,
			"token_endpoint": %q,
			"jwks_uri": %q
		}`, srvURL, srvURL+"/a", srvURL+"/t", srvURL+"/j")
	}))
	srvURL = srv.URL
	defer srv.Close()
	// Caller asks for "https://id.example/" (trailing slash); document
	// returns the bare form. The OIDC requirement is exact match.
	if _, err := oauth.Discover(context.Background(), srv.URL+"/", nil); err == nil {
		t.Error("Discover must reject the trimmed form when the caller asked with a trailing slash")
	}
}
