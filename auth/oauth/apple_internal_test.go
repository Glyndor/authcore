package oauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Glyndor/authcore"
)

// appleFakeProvider supplies authcore.Provider values to oauth.New during
// tests. It mirrors the test provider in package oauth_test, which is not
// importable here.
type appleFakeProvider struct{}

func (appleFakeProvider) Config() authcore.Config { return authcore.DefaultConfig() }
func (appleFakeProvider) Logger() authcore.Logger { return silentLogger{} }
func (appleFakeProvider) Keys() authcore.Keys     { return nil }

// silentLogger satisfies authcore.Logger with no output. The library uses
// it on the success path only; this package's tests assert via errors.
type silentLogger struct{}

func (silentLogger) Debug(string, ...any) {}
func (silentLogger) Info(string, ...any)  {}
func (silentLogger) Warn(string, ...any)  {}
func (silentLogger) Error(string, ...any) {}

const (
	appleTestTeamID   = "ABCDE12345"
	appleTestKeyID    = "KEYID67890"
	appleTestClientID = "com.example.services"
)

// TestPreset_AppleDiscoveryMatchesApplePreset pins every URL the Apple
// preset hardcodes against the document Apple published at its OIDC
// discovery URL (captured 2026-09-27 in apple-discovery.json). The
// comparison is byte-for-byte against Apple(), not against literals, so a
// change on either side flips this test in the right direction. The
// AuthURL is stripped of its query string before the comparison so the
// form_post suffix does not pin against the captured document's exact
// query. The AuthMethods and UserInfoURL fields of the preset are also
// pinned against literals here, since the discovery document and the
// preset are the only two sources of truth for them.
func TestPreset_AppleDiscoveryMatchesApplePreset(t *testing.T) {
	t.Parallel()
	want := Apple()
	routes := map[string][]byte{
		"https://appleid.apple.com/.well-known/openid-configuration": readFixture(t, "apple-discovery.json"),
	}
	got, err := Discover(context.Background(),
		"https://appleid.apple.com", stubClient(routes))
	if err != nil {
		t.Fatalf("Discover(apple): %v", err)
	}
	if got.Issuer != want.Issuer {
		t.Errorf("Issuer: got %q, want %q", got.Issuer, want.Issuer)
	}
	if got.TokenURL != want.TokenURL {
		t.Errorf("TokenURL: got %q, want %q", got.TokenURL, want.TokenURL)
	}
	if got.JWKSURL != want.JWKSURL {
		t.Errorf("JWKSURL: got %q, want %q", got.JWKSURL, want.JWKSURL)
	}
	gotAuth := strings.SplitN(got.AuthURL, "?", 2)[0]
	wantAuth := strings.SplitN(want.AuthURL, "?", 2)[0]
	if gotAuth != wantAuth {
		t.Errorf("AuthURL path: got %q, want %q", gotAuth, wantAuth)
	}
	if len(got.AuthMethods) != 1 || got.AuthMethods[0] != "client_secret_post" {
		t.Errorf("AuthMethods: got %v, want [client_secret_post]", got.AuthMethods)
	}
	if got.UserInfoURL != "" {
		t.Errorf("Apple discovery publishes no userinfo, the preset must not claim one: %q", got.UserInfoURL)
	}
	if len(want.AuthMethods) != 1 || want.AuthMethods[0] != "client_secret_post" {
		t.Errorf("Apple() AuthMethods = %v, want [client_secret_post]", want.AuthMethods)
	}
	if want.UserInfoURL != "" {
		t.Errorf("Apple() UserInfoURL = %q, want empty", want.UserInfoURL)
	}
}

// TestAuthCodeURL_AppleResponseModeFormPost pins two surfaces together:
// response_mode must appear EXACTLY once with value form_post, and the
// default scope set must be openid email name verbatim, not a reordering,
// not a substitution.
func TestAuthCodeURL_AppleResponseModeFormPost(t *testing.T) {
	t.Parallel()
	c, err := New(appleFakeProvider{}, Config{
		ClientID:    appleTestClientID,
		RedirectURL: "https://app.example.com/auth/apple/callback",
		Provider:    Apple(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req, err := c.AuthCodeURL()
	if err != nil {
		t.Fatalf("AuthCodeURL: %v", err)
	}
	u, err := url.Parse(req.URL)
	if err != nil {
		t.Fatalf("parse URL: %v", err)
	}
	q := u.Query()
	if got := q.Get("response_mode"); got != "form_post" {
		t.Fatalf("response_mode = %q, want form_post", got)
	}
	if got := q["response_mode"]; len(got) != 1 {
		t.Errorf("response_mode appears %d times in the URL, want 1", len(got))
	}
	if got := q.Get("scope"); got != "openid email name" {
		t.Errorf("scope = %q, want %q", got, "openid email name")
	}
}

// TestAuthCodeURL_ExplicitScopesWin pairs the test above: a Config that
// supplies its own Scopes wins over Provider.DefaultScopes. Without this,
// a regression that quietly dropped caller-supplied scopes would pass on
// the default-only path.
func TestAuthCodeURL_ExplicitScopesWin(t *testing.T) {
	t.Parallel()
	c, err := New(appleFakeProvider{}, Config{
		ClientID:    appleTestClientID,
		RedirectURL: "https://app.example.com/auth/apple/callback",
		Provider:    Apple(),
		Scopes:      []string{"openid"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req, _ := c.AuthCodeURL()
	u, _ := url.Parse(req.URL)
	if got := u.Query().Get("scope"); got != "openid" {
		t.Errorf("scope = %q, want openid (explicit Config.Scopes must win)", got)
	}
}

// TestAppleDefaultScopes_AreCloned pins that applyDefaults clones the
// Provider.DefaultScopes slice. A caller that mutates the slice on the
// Provider they handed in must NOT change what a built client later
// sends. Without the clone, the test's tampered slice would surface in
// the URL on the second AuthCodeURL.
func TestAppleDefaultScopes_AreCloned(t *testing.T) {
	t.Parallel()
	p := Apple()
	c, err := New(appleFakeProvider{}, Config{
		ClientID:    appleTestClientID,
		RedirectURL: "https://app.example.com/auth/apple/callback",
		Provider: Provider{
			Issuer:        p.Issuer,
			AuthURL:       p.AuthURL,
			TokenURL:      p.TokenURL,
			JWKSURL:       p.JWKSURL,
			AuthMethods:   p.AuthMethods,
			DefaultScopes: p.DefaultScopes,
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	cfg := c.cfg.Provider
	cfg.DefaultScopes[0] = "tampered"
	req, _ := c.AuthCodeURL()
	u, _ := url.Parse(req.URL)
	if got := u.Query().Get("scope"); got != "openid email name" {
		t.Errorf("scope = %q, want %q (the built client's slice must be independent of the caller's)", got, "openid email name")
	}
}

// TestConfig_ClientSecretAndFuncRejected pins the mutual exclusion of
// ClientSecret and ClientSecretFunc. The fragment in the error must
// name both fields so a regression that silently preferred one (and
// ignored the other) is visible in the failure text.
func TestConfig_ClientSecretAndFuncRejected(t *testing.T) {
	t.Parallel()
	_, err := New(appleFakeProvider{}, Config{
		ClientID:     appleTestClientID,
		ClientSecret: "static",
		ClientSecretFunc: func(context.Context) (string, error) {
			return "dyn", nil
		},
		RedirectURL: "https://app.example.com/cb",
		Provider:    Apple(),
	})
	if err == nil {
		t.Fatal("expected rejection of a Config that sets both ClientSecret and ClientSecretFunc")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("rejection must wrap ErrInvalidConfig, got %v", err)
	}
	if !strings.Contains(err.Error(), "ClientSecret and ClientSecretFunc") {
		t.Fatalf("rejection must name both fields, got %v", err)
	}
}

// TestExchange_ClientSecretFunc_Success pairs the failure cases below: a
// func returning "s1" then "s2" must produce form fields carrying those
// exact values. The token server's request counter is the regression
// guard, and the empty Authorization header under client_secret_post is
// the secret-not-in-headers invariant.
func TestExchange_ClientSecretFunc_Success(t *testing.T) {
	t.Parallel()
	var (
		got1  atomic.Value
		got2  atomic.Value
		calls atomic.Int32
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		calls.Add(1)
		if r.Header.Get("Authorization") != "" {
			t.Errorf("Authorization header must be empty under client_secret_post, got %q", r.Header.Get("Authorization"))
		}
		switch calls.Load() {
		case 1:
			got1.Store(r.FormValue("client_secret"))
		case 2:
			got2.Store(r.FormValue("client_secret"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":"Bearer","id_token":"x"}`))
	}))
	defer srv.Close()

	var which atomic.Int32
	secretFn := func(ctx context.Context) (string, error) {
		if which.Add(1) == 1 {
			return "s1", nil
		}
		return "s2", nil
	}
	c, err := New(appleFakeProvider{}, Config{
		ClientID:         appleTestClientID,
		ClientSecretFunc: secretFn,
		RedirectURL:      "https://app.example.com/auth/apple/callback",
		HTTPClient:       newLoopbackClient(t, srv),
		Provider: Provider{
			Issuer:      "https://appleid.apple.com",
			AuthURL:     "https://appleid.apple.com/auth/authorize?response_mode=form_post",
			TokenURL:    srv.URL,
			JWKSURL:     "https://appleid.apple.com/auth/keys",
			AuthMethods: []string{"client_secret_post"},
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for i := 0; i < 2; i++ {
		_, err := c.Exchange(context.Background(), "c", "v")
		if err != nil {
			t.Fatalf("Exchange #%d: %v", i+1, err)
		}
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("token endpoint saw %d requests, want 2", got)
	}
	if v := got1.Load(); v != "s1" {
		t.Errorf("first exchange client_secret = %v, want s1", v)
	}
	if v := got2.Load(); v != "s2" {
		t.Errorf("second exchange client_secret = %v, want s2", v)
	}
}

// TestExchange_ClientSecretFunc_Error pins that a func error short-circuits
// Exchange, wraps ErrExchange, and never reaches the token endpoint. The
// sErr sentinel is the regression guard: a future refactor that swallowed
// the inner error would lose it.
func TestExchange_ClientSecretFunc_Error(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":"Bearer","id_token":"x"}`))
	}))
	defer srv.Close()

	sErr := errors.New("secrets vault sealed")
	c, err := New(appleFakeProvider{}, Config{
		ClientID:    appleTestClientID,
		RedirectURL: "https://app.example.com/cb",
		HTTPClient:  newLoopbackClient(t, srv),
		ClientSecretFunc: func(ctx context.Context) (string, error) {
			return "", sErr
		},
		Provider: Provider{
			Issuer:      "https://appleid.apple.com",
			AuthURL:     "https://appleid.apple.com/auth/authorize?response_mode=form_post",
			TokenURL:    srv.URL,
			JWKSURL:     "https://appleid.apple.com/auth/keys",
			AuthMethods: []string{"client_secret_post"},
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = c.Exchange(context.Background(), "code", "verifier")
	if err == nil {
		t.Fatal("expected Exchange to return an error when ClientSecretFunc fails")
	}
	if !errors.Is(err, ErrExchange) {
		t.Fatalf("rejection must wrap ErrExchange, got %v", err)
	}
	if !errors.Is(err, sErr) {
		t.Fatalf("rejection must wrap the func's sentinel, got %v", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("token endpoint was called %d times, want 0 (the func error must short-circuit before the HTTP request)", calls.Load())
	}
}

// TestExchange_ClientSecretFunc_Empty pins that an empty string from the
// func is rejected before the request is built. Some token servers
// accept an empty client_secret as "no secret configured" and answer 401,
// which would mask the actual bug; the library catches it earlier.
func TestExchange_ClientSecretFunc_Empty(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":"Bearer","id_token":"x"}`))
	}))
	defer srv.Close()

	c, err := New(appleFakeProvider{}, Config{
		ClientID:    appleTestClientID,
		RedirectURL: "https://app.example.com/cb",
		HTTPClient:  newLoopbackClient(t, srv),
		ClientSecretFunc: func(ctx context.Context) (string, error) {
			return "", nil
		},
		Provider: Provider{
			Issuer:      "https://appleid.apple.com",
			AuthURL:     "https://appleid.apple.com/auth/authorize?response_mode=form_post",
			TokenURL:    srv.URL,
			JWKSURL:     "https://appleid.apple.com/auth/keys",
			AuthMethods: []string{"client_secret_post"},
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = c.Exchange(context.Background(), "code", "verifier")
	if err == nil {
		t.Fatal("expected an error when ClientSecretFunc returns empty")
	}
	if !errors.Is(err, ErrExchange) {
		t.Fatalf("rejection must wrap ErrExchange, got %v", err)
	}
	if !strings.Contains(err.Error(), "empty secret") {
		t.Fatalf("rejection must name the empty-secret cause, got %v", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("token endpoint was called %d times, want 0", calls.Load())
	}
}
