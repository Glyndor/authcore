package discovery_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth/internal/discovery"
)

var errFuzzDiscovery = errors.New("oauth: OIDC discovery failed")

type fuzzRoundTrip func(*http.Request) (*http.Response, error)

func (f fuzzRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// fuzzEndpointOK is the rule an accepted endpoint must satisfy, written
// without the code under test: a hierarchical URL with a host that is https,
// or plain http to a loopback host.
func fuzzEndpointOK(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" || u.Host == "" {
		return false
	}
	switch u.Scheme {
	case "https":
		return true
	case "http":
		if u.Hostname() == "localhost" {
			return true
		}
		addr, err := netip.ParseAddr(u.Hostname())
		return err == nil && addr.IsLoopback()
	}
	return false
}

const fuzzDoc = `{"issuer":"https://issuer.example","authorization_endpoint":"https://issuer.example/auth","token_endpoint":"https://issuer.example/token","jwks_uri":"https://issuer.example/jwks","userinfo_endpoint":"https://issuer.example/userinfo","token_endpoint_auth_methods_supported":["client_secret_basic"]}`

// FuzzFetch serves arbitrary bytes as the discovery document of an arbitrary
// issuer string. Whatever comes back: no panic, every refusal wraps the
// discovery sentinel, and an accepted document echoes the requested issuer
// exactly and carries only endpoints that are https (or loopback http).
func FuzzFetch(f *testing.F) {
	f.Add([]byte(fuzzDoc), "https://issuer.example")
	f.Add([]byte(fuzzDoc), "https://issuer.example/")
	f.Add([]byte(`{"issuer":"http://127.0.0.1:1","authorization_endpoint":"http://127.0.0.1:1/a","token_endpoint":"http://127.0.0.1:1/t","jwks_uri":"http://127.0.0.1:1/j"}`), "http://127.0.0.1:1")
	f.Add([]byte(`{"issuer":"https://issuer.example","authorization_endpoint":"http://169.254.169.254/","token_endpoint":"https://x/t","jwks_uri":"https://x/j"}`), "https://issuer.example")
	f.Add([]byte(`{"issuer":"https://issuer.example","authorization_endpoint":"//x","token_endpoint":"https:x","jwks_uri":"https:///j"}`), "https://issuer.example")
	f.Add([]byte(`[]`), "https://issuer.example")
	f.Add([]byte(`{"issuer":`), "")
	f.Add([]byte{}, "ftp://x")

	f.Fuzz(func(t *testing.T, body []byte, issuer string) {
		hc := &http.Client{Transport: fuzzRoundTrip(func(r *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(body)), Request: r}, nil
		})}
		doc, err := discovery.Fetch(context.Background(), issuer, hc, errFuzzDiscovery)
		if err != nil {
			if !errors.Is(err, errFuzzDiscovery) {
				t.Fatalf("a refusal that does not wrap the discovery sentinel: %v", err)
			}
			return
		}
		if doc.Issuer != issuer {
			t.Fatalf("accepted issuer %q for a request about %q", doc.Issuer, issuer)
		}
		if doc.AuthURL == "" || doc.TokenURL == "" || doc.JWKSURL == "" {
			t.Fatalf("accepted a document without its required endpoints: %+v", doc)
		}
		for _, raw := range []string{doc.AuthURL, doc.TokenURL, doc.JWKSURL, doc.UserInfoURL} {
			if raw != "" && !fuzzEndpointOK(raw) {
				t.Fatalf("accepted the endpoint %q", raw)
			}
		}
		if !fuzzEndpointOK(issuer) {
			t.Fatalf("accepted a document for the issuer %q, which is not an https or loopback URL", issuer)
		}
	})
}
