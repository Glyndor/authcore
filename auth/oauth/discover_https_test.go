package oauth_test

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

// countingTransport records every RoundTrip call and returns a sentinel
// error. It is wired into an http.Client by the issuer-https test below to
// prove that Discover refuses a plaintext issuer before the network is
// touched.
type countingTransport struct {
	calls int
}

func (c *countingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	c.calls++
	return nil, fmt.Errorf("transport must not be called")
}

// TestDiscover_issuerMustBeHTTPSBeforeFetch pins the early exit on the
// issuer scheme. The transport is wired so any call would increment a
// counter and return an error; the assertion that the counter stays at 0
// is the proof, separate from the error message, that the fetch was not
// made.
func TestDiscover_issuerMustBeHTTPSBeforeFetch(t *testing.T) {
	tr := &countingTransport{}
	client := &http.Client{Transport: tr}
	_, err := oauth.Discover(context.Background(), "http://id.example", client)
	if !errors.Is(err, oauth.ErrDiscovery) {
		t.Fatalf("expected ErrDiscovery, got %v", err)
	}
	if !strings.Contains(err.Error(), "issuer must use https") {
		t.Fatalf("refusal must name the rule (want issuer must use https), got %v", err)
	}
	if tr.calls != 0 {
		t.Fatalf("transport was called %d times; the issuer scheme must be checked before any fetch", tr.calls)
	}
}

// TestDiscover_endpointMustBeHTTPS pins the same rule on the endpoints
// returned by the document. A discovery document whose jwks_uri points at a
// plaintext, non-loopback host is refused after a successful fetch, so the
// trust chain (the URL the signature hangs on) cannot be downgraded. The
// acceptance pair builds the identical document with an https jwks_uri and
// confirms JWKSURL equals it on the returned Provider.
func TestDiscover_endpointMustBeHTTPS(t *testing.T) {
	var srvURL string
	makeServer := func(jwks string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration") {
				http.NotFound(w, r)
				return
			}
			fmt.Fprintf(w, `{
				"issuer": %q,
				"authorization_endpoint": "https://id.example/auth",
				"token_endpoint": "https://id.example/token",
				"jwks_uri": %q,
				"userinfo_endpoint": "https://id.example/userinfo"
			}`, srvURL, jwks)
		}))
	}

	t.Run("rejection: jwks_uri is plaintext", func(t *testing.T) {
		srv := makeServer("http://keys.example/jwks")
		srvURL = srv.URL
		defer srv.Close()
		_, err := oauth.Discover(context.Background(), srv.URL, nil)
		if !errors.Is(err, oauth.ErrDiscovery) {
			t.Fatalf("expected ErrDiscovery, got %v", err)
		}
		if !strings.Contains(err.Error(), "jwks_uri must use https") {
			t.Fatalf("refusal must name the field (want jwks_uri must use https), got %v", err)
		}
	})

	t.Run("acceptance: jwks_uri is https", func(t *testing.T) {
		srv := makeServer("https://keys.example/jwks")
		srvURL = srv.URL
		defer srv.Close()
		p, err := oauth.Discover(context.Background(), srv.URL, nil)
		if err != nil {
			t.Fatalf("acceptance: Discover, got %v", err)
		}
		if p.JWKSURL != "https://keys.example/jwks" {
			t.Fatalf("acceptance: JWKSURL = %q, want https://keys.example/jwks", p.JWKSURL)
		}
	})
}
