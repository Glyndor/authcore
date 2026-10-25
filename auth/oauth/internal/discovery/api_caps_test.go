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
	"github.com/Glyndor/authcore/auth/oauth/internal/oauthtest"
)

func TestResponseCap_discoverAtCap(t *testing.T) {
	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(writeAtCap(srvURL, oauthtest.ResponseCap))
	}))
	srvURL = srv.URL
	defer srv.Close()

	body := writeAtCap(srvURL, oauthtest.ResponseCap)
	if len(body) != oauthtest.ResponseCap {
		t.Fatalf("test fixture drifted: body is %d bytes, want %d", len(body), oauthtest.ResponseCap)
	}

	p, err := oauth.Discover(context.Background(), srv.URL, nil)
	if err != nil {
		t.Fatalf("acceptance at cap: Discover, got %v", err)
	}
	if p.JWKSURL != srv.URL+"/jwks" {
		t.Fatalf("acceptance: JWKSURL = %q, want %q", p.JWKSURL, srv.URL+"/jwks")
	}
}

func TestResponseCap_discoverOverCap(t *testing.T) {
	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(writeOverCap(srvURL, oauthtest.ResponseCap))
	}))
	srvURL = srv.URL
	defer srv.Close()

	body := writeOverCap(srvURL, oauthtest.ResponseCap)
	if len(body) != oauthtest.ResponseCap+1 {
		t.Fatalf("test fixture drifted: body is %d bytes, want %d", len(body), oauthtest.ResponseCap+1)
	}

	_, err := oauth.Discover(context.Background(), srv.URL, nil)
	if !errors.Is(err, oauth.ErrDiscovery) {
		t.Fatalf("expected ErrDiscovery, got %v", err)
	}
}

// writeAtCap returns a discovery document body of EXACTLY limit bytes. The
// issuer and jwks_uri use the server's URL, so the test sets srvURL after
// httptest.NewServer returns and the handler closes over it.
func writeAtCap(srvURL string, limit int) []byte {
	prefix := fmt.Sprintf(`{"issuer":%q,"authorization_endpoint":"https://id.example/auth","token_endpoint":"https://id.example/token","jwks_uri":%q,"userinfo_endpoint":"https://id.example/userinfo","pad":"`, srvURL, srvURL+"/jwks")
	suffix := `"}`
	return oauthtest.PaddedBodyAt(limit, prefix, suffix)
}

// writeOverCap returns a discovery document body of EXACTLY limit+1 bytes.
func writeOverCap(srvURL string, limit int) []byte {
	prefix := fmt.Sprintf(`{"issuer":%q,"authorization_endpoint":"https://id.example/auth","token_endpoint":"https://id.example/token","jwks_uri":%q,"userinfo_endpoint":"https://id.example/userinfo","pad":"`, srvURL, srvURL+"/jwks")
	suffix := `"}`
	return oauthtest.PaddedBodyOver(limit, prefix, suffix)
}
