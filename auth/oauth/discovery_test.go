package oauth_test

import (
	"context"
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
		w.WriteHeader(http.StatusNotFound)
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
