package discovery_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth/internal/discovery"
)

var errDiscovery = errors.New("discovery failed")

type stub func(*http.Request) (*http.Response, error)

func (f stub) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func serving(status int, body string, seen *http.Request) *http.Client {
	return &http.Client{Transport: stub(func(r *http.Request) (*http.Response, error) {
		if seen != nil {
			*seen = *r
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}, nil
	})}
}

func document(issuer, endpointHost string) string {
	return `{"issuer":"` + issuer + `","authorization_endpoint":"https://` + endpointHost + `/auth",` +
		`"token_endpoint":"https://` + endpointHost + `/token","jwks_uri":"https://` + endpointHost + `/jwks"}`
}

func TestFetchAcceptsOnlySuccessStatuses(t *testing.T) {
	t.Parallel()
	const issuer = "https://provider.example"
	for status, ok := range map[int]bool{199: false, 200: true, 299: true, 300: false, 301: false, 500: false} {
		_, err := discovery.Fetch(context.Background(), issuer, serving(status, document(issuer, "provider.example"), nil), errDiscovery)
		if (err == nil) != ok {
			t.Errorf("status %d: accepted=%v, want %v (err=%v)", status, err == nil, ok, err)
		}
	}
}

func TestFetchAsksForJSONAtTheWellKnownPath(t *testing.T) {
	t.Parallel()
	const issuer = "https://provider.example/tenant/"
	var seen http.Request
	if _, err := discovery.Fetch(context.Background(), issuer, serving(200, document(issuer, "provider.example"), &seen), errDiscovery); err != nil {
		t.Fatal(err)
	}
	if got := seen.Header.Get("Accept"); got != "application/json" {
		t.Errorf("Accept = %q", got)
	}
	if got := seen.URL.String(); got != "https://provider.example/tenant/.well-known/openid-configuration" {
		t.Errorf("requested %q", got)
	}
}

// Only an issuer that is itself a loopback host vouches for loopback
// endpoints. A public issuer whose document points inward is refused.
func TestFetchKeepsAPublicIssuersEndpointsOffLoopback(t *testing.T) {
	t.Parallel()
	const issuer = "https://provider.example"
	_, err := discovery.Fetch(context.Background(), issuer, serving(200, document(issuer, "localhost"), nil), errDiscovery)
	if err == nil || !errors.Is(err, errDiscovery) || !strings.Contains(err.Error(), "internal address") {
		t.Fatalf("a public issuer must not vouch for a loopback endpoint, got: %v", err)
	}
	// The same document is fine when the operator opted into private networks.
	if _, err := discovery.FetchWith(context.Background(), issuer, serving(200, document(issuer, "localhost"), nil), errDiscovery, true); err != nil {
		t.Fatalf("AllowPrivateNetwork must admit it: %v", err)
	}
}

func TestFetchRefusesARequestThatCannotBeBuilt(t *testing.T) {
	t.Parallel()
	var noCtx context.Context
	_, err := discovery.Fetch(noCtx, "https://provider.example", serving(200, `{}`, nil), errDiscovery)
	if !errors.Is(err, errDiscovery) {
		t.Fatalf("err = %v, want the discovery sentinel", err)
	}
}
