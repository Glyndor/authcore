package clientauth_test

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth"
	"github.com/Glyndor/authcore/auth/oauth/internal/oauthtest"
)

// ---- Google preset accepts both issuer spellings ---------------------------

// ---- Microsoft preset rejects a non-GUID tenant with a GUID-named error ----

// ---- Exchange uses the client auth method the provider advertises ----------

// TestExchange_sendsBasicAuthHeaderWhenAdvertised pins the path where
// discovery advertises "client_secret_basic" and Exchange sends the secret in
// the Authorization header. The provider's recorded credentials and the body
// (which is asserted to carry no client_secret) prove the channel.
func TestExchange_sendsBasicAuthHeaderWhenAdvertised(t *testing.T) {
	const (
		clientID     = "cid-basic"
		clientSecret = "shh-basic"
	)
	var sawAuth string
	var sawForm url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		_ = r.ParseForm()
		sawForm = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":"Bearer","id_token":"idt"}`))
	}))
	defer srv.Close()

	c, err := oauth.New(oauthtest.FakeProvider{}, oauth.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  "https://app.example/cb",
		Scopes:       []string{"openid"},
		Provider: oauth.Provider{
			AuthURL:     srv.URL + "/a",
			TokenURL:    srv.URL,
			JWKSURL:     srv.URL,
			Issuer:      srv.URL,
			AuthMethods: []string{"client_secret_basic"},
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := c.Exchange(context.Background(), "code", "verifier"); err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(clientID+":"+clientSecret))
	if sawAuth != wantAuth {
		t.Errorf("Authorization header = %q, want %q", sawAuth, wantAuth)
	}
	if c := sawForm.Get("client_secret"); c != "" {
		t.Errorf("client_secret must not appear in the body, got %q", c)
	}
}

// TestExchange_keepsPostWhenNothingAdvertised pins the compatibility rule: a
// provider that advertises no authentication method tells us nothing, so
// Exchange keeps sending the secret in the body, which is what this library
// sent before it could choose. Switching such a provider to Basic would break
// every hand-configured token endpoint that only accepts Post.
func TestExchange_keepsPostWhenNothingAdvertised(t *testing.T) {
	const (
		clientID     = "cid-default"
		clientSecret = "shh-default"
	)
	var sawAuth string
	var sawForm url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		_ = r.ParseForm()
		sawForm = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":"Bearer","id_token":"idt"}`))
	}))
	defer srv.Close()

	c, err := oauth.New(oauthtest.FakeProvider{}, oauth.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  "https://app.example/cb",
		Scopes:       []string{"openid"},
		Provider: oauth.Provider{
			AuthURL:  srv.URL + "/a",
			TokenURL: srv.URL,
			JWKSURL:  srv.URL,
			Issuer:   srv.URL,
			// AuthMethods intentionally absent: OIDC default applies.
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := c.Exchange(context.Background(), "code", "verifier"); err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if sawAuth != "" {
		t.Errorf("no method advertised: the secret must stay in the body, got Authorization %q", sawAuth)
	}
	if got := sawForm.Get("client_secret"); got != clientSecret {
		t.Errorf("client_secret in body = %q, want the configured secret", got)
	}
}

// TestExchange_sendsPostOnlyWhenBasicIsNotAdvertised pins the path where the
// provider advertises only "client_secret_post": Exchange sends it in the body,
// and the Authorization header is empty.
func TestExchange_sendsPostOnlyWhenBasicIsNotAdvertised(t *testing.T) {
	const (
		clientID     = "cid-post"
		clientSecret = "shh-post"
	)
	var sawAuth string
	var sawForm url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		_ = r.ParseForm()
		sawForm = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":"Bearer","id_token":"idt"}`))
	}))
	defer srv.Close()

	c, err := oauth.New(oauthtest.FakeProvider{}, oauth.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  "https://app.example/cb",
		Scopes:       []string{"openid"},
		Provider: oauth.Provider{
			AuthURL:     srv.URL + "/a",
			TokenURL:    srv.URL,
			JWKSURL:     srv.URL,
			Issuer:      srv.URL,
			AuthMethods: []string{"client_secret_post"},
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := c.Exchange(context.Background(), "code", "verifier"); err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if sawAuth != "" {
		t.Errorf("Authorization header must be empty under Post, got %q", sawAuth)
	}
	if got, want := sawForm.Get("client_secret"), clientSecret; got != want {
		t.Errorf("client_secret in body = %q, want %q", got, want)
	}
}

// TestExchange_refusesUnsupplicableAuthMethod pins the path where the
// provider advertises only methods the library does not implement (e.g.
// "private_key_jwt"). Exchange must fail before any request leaves the
// machine, so the client secret is never sent on an unrecognised channel.
func TestExchange_refusesUnsupplicableAuthMethod(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":"Bearer","id_token":"idt"}`))
	}))
	defer srv.Close()

	c, err := oauth.New(oauthtest.FakeProvider{}, oauth.Config{
		ClientID:     "cid-jwk",
		ClientSecret: "shh-jwk",
		RedirectURL:  "https://app.example/cb",
		Scopes:       []string{"openid"},
		Provider: oauth.Provider{
			AuthURL:     srv.URL + "/a",
			TokenURL:    srv.URL,
			JWKSURL:     srv.URL,
			Issuer:      srv.URL,
			AuthMethods: []string{"private_key_jwt"},
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	var exchangeErr error
	if _, exchangeErr = c.Exchange(context.Background(), "code", "verifier"); exchangeErr == nil {
		t.Fatal("Exchange must refuse when only unsupported methods are advertised")
	}
	if !strings.Contains(exchangeErr.Error(), "supported") {
		t.Errorf("refusal must name the missing support, got %v", exchangeErr)
	}
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Errorf("token endpoint was hit %d times; an unsupplicable auth method must short-circuit", got)
	}
}

// ---- URL validation: opaque, empty host, fragment ---------------------------

// ---- AuthCodeURL: parameter merging and dedup --------------------------------

// ---- supplied HTTPClient: zero timeout gets the library default ------------

// ---- Discovery: trailing-slash issuer rejected (exact match only) ----------
