package clientauth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth"
	"github.com/Glyndor/authcore/auth/oauth/internal/oauthtest"
)

// basicTokenServer answers the token request and records the Basic
// credentials as an RFC 6749 server reads them: base64, then form-decoded.
func basicTokenServer(t *testing.T, gotID, gotSecret *string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, secret, ok := r.BasicAuth()
		if !ok {
			http.Error(w, "no basic auth", http.StatusUnauthorized)
			return
		}
		var err error
		if *gotID, err = url.QueryUnescape(id); err != nil {
			t.Errorf("client id is not form-encoded: %v", err)
		}
		if *gotSecret, err = url.QueryUnescape(secret); err != nil {
			t.Errorf("client secret is not form-encoded: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":"Bearer"}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func basicClient(t *testing.T, srv *httptest.Server, id, secret string, methods []string) *oauth.Client {
	t.Helper()
	c, err := oauth.New(oauthtest.FakeProvider{}, oauth.Config{
		ClientID: id, ClientSecret: secret, RedirectURL: "https://app.example.com/cb",
		Provider: oauth.Provider{
			AuthURL: srv.URL + "/a", TokenURL: srv.URL + "/t", UserInfoURL: srv.URL + "/u",
			AuthMethods: methods,
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestExchange_formEncodesBasicCredentials(t *testing.T) {
	for _, tc := range []struct{ id, secret string }{
		{"my:client", "a+b%2Fc d"},    // every character that changes meaning
		{"client-123", "Ab3_x.y~Z-9"}, // the usual shape, which encoding leaves as is
	} {
		var gotID, gotSecret string
		srv := basicTokenServer(t, &gotID, &gotSecret)
		c := basicClient(t, srv, tc.id, tc.secret, []string{"client_secret_basic"})
		if _, err := c.Exchange(context.Background(), "code", "verifier"); err != nil {
			t.Fatalf("Exchange(%q): %v", tc.id, err)
		}
		if gotID != tc.id || gotSecret != tc.secret {
			t.Errorf("server read id %q secret %q, want %q %q", gotID, gotSecret, tc.id, tc.secret)
		}
	}
}

func TestNew_copiesTheAdvertisedAuthMethods(t *testing.T) {
	var gotID, gotSecret string
	srv := basicTokenServer(t, &gotID, &gotSecret)
	methods := []string{"client_secret_basic"}
	c := basicClient(t, srv, "client-123", "s3cret", methods)
	methods[0] = "private_key_jwt" // the caller reuses its slice after New

	if _, err := c.Exchange(context.Background(), "code", "verifier"); err != nil {
		t.Fatalf("Exchange after the caller changed its slice: %v", err)
	}
	if gotSecret != "s3cret" {
		t.Fatalf("server read secret %q over Basic, want the configured one", gotSecret)
	}
}
