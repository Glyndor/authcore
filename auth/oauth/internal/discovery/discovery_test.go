package discovery

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type brokenBody struct{}

func (brokenBody) Read([]byte) (int, error) { return 0, errors.New("connection reset") }
func (brokenBody) Close() error             { return nil }

func respond(code int, body string) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
}

const issuer = "https://p.example"

func docJSON(overrides ...string) string {
	fields := map[string]string{
		"issuer":                 `"` + issuer + `"`,
		"authorization_endpoint": `"https://p.example/auth"`,
		"token_endpoint":         `"https://p.example/token"`,
		"jwks_uri":               `"https://p.example/jwks"`,
		"userinfo_endpoint":      `"https://p.example/userinfo"`,
	}
	for i := 0; i+1 < len(overrides); i += 2 {
		fields[overrides[i]] = overrides[i+1]
	}
	var parts []string
	for k, v := range fields {
		parts = append(parts, `"`+k+`":`+v)
	}
	return `{` + strings.Join(parts, ",") + `,"token_endpoint_auth_methods_supported":["client_secret_basic"]}`
}

func TestFetchReturnsTheDocument(t *testing.T) {
	t.Parallel()
	var gotURL string
	h := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		gotURL = r.URL.String()
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(docJSON()))}, nil
	})}
	doc, err := Fetch(context.Background(), issuer+"/", h, ErrDiscovery)
	if err == nil {
		t.Fatalf("a trailing slash on the requested issuer must not match the document's issuer; got %+v", doc)
	}
	doc, err = Fetch(context.Background(), issuer, h, ErrDiscovery)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if gotURL != issuer+"/.well-known/openid-configuration" {
		t.Errorf("fetched %q", gotURL)
	}
	if doc.Issuer != issuer || doc.AuthURL != "https://p.example/auth" || doc.TokenURL != "https://p.example/token" ||
		doc.JWKSURL != "https://p.example/jwks" || doc.UserInfoURL != "https://p.example/userinfo" ||
		len(doc.AuthMethods) != 1 || doc.AuthMethods[0] != "client_secret_basic" {
		t.Errorf("document = %+v", doc)
	}
}

func TestFetchRefusals(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		issuer string
		client *http.Client
		want   string
	}{
		{"plaintext issuer", "http://p.example", respond(200, docJSON()), "must use https"},
		{"unbuildable request", "https://p.example\x7f", respond(200, docJSON()), "issuer"},
		{"transport error", issuer, &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("dial failed")
		})}, "dial failed"},
		{"read error", issuer, &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: brokenBody{}}, nil
		})}, "read:"},
		{"non-2xx", issuer, respond(404, docJSON()), "status 404"},
		{"undecodable", issuer, respond(200, `nope`), "decode:"},
		{"issuer mismatch", issuer, respond(200, docJSON("issuer", `"https://other.example"`)), "issuer mismatch"},
		{"missing endpoints", issuer, respond(200, docJSON("jwks_uri", `""`)), "missing required endpoints"},
		{"plaintext endpoint", issuer, respond(200, docJSON("token_endpoint", `"http://p.example/token"`)), "token_endpoint must use https"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := Fetch(context.Background(), tc.issuer, tc.client, ErrDiscovery)
			if !errors.Is(err, ErrDiscovery) {
				t.Fatalf("err = %v, want errors.Is(..., ErrDiscovery)", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

// TestFetchBuildsADefaultClientWhenNoneIsSupplied reaches the nil-client
// branch without a network: a cancelled context fails the request first.
func TestFetchBuildsADefaultClientWhenNoneIsSupplied(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Fetch(ctx, issuer, nil, ErrDiscovery); !errors.Is(err, ErrDiscovery) {
		t.Fatalf("err = %v, want errors.Is(..., ErrDiscovery)", err)
	}
}
