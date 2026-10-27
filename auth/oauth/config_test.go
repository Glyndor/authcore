package oauth_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth"
	"github.com/Glyndor/authcore/auth/oauth/internal/oauthtest"
)

func TestNew_invalidConfigRejected(t *testing.T) {
	cases := map[string]oauth.Config{
		"no client id": {RedirectURL: "https://app.example/cb", Provider: oauth.Google()},
		"no redirect":  {ClientID: "x", Provider: oauth.Google()},
		"no provider":  {ClientID: "x", RedirectURL: "https://app.example/cb"},
	}
	for name, cfg := range cases {
		if _, err := oauth.New(oauthtest.FakeProvider{}, cfg); err == nil {
			t.Errorf("%s: expected ErrInvalidConfig", name)
		}
	}
}
func TestNew_rejectsJWKSWithoutIssuerCheck(t *testing.T) {
	// JWKSURL + UserInfoURL + empty Issuer + nil IssuerValidator was accepted
	// before validateConfig changed: the half-configured check was gated on
	// !oauth2, so UserInfoURL hid the missing iss check.
	base := oauth.Config{
		ClientID:    oauthtest.ClientID,
		RedirectURL: "https://app.example/cb",
		Scopes:      []string{"read:user"},
		Provider: oauth.Provider{
			AuthURL:     "https://provider.example/auth",
			TokenURL:    "https://provider.example/token",
			JWKSURL:     "https://provider.example/jwks",
			UserInfoURL: "https://provider.example/userinfo",
		},
	}
	if _, err := oauth.New(oauthtest.FakeProvider{}, base); !errors.Is(err, oauth.ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig, got %v", err)
	}
	// Acceptance pair: the same config with an issuer must construct.
	base.Provider.Issuer = "https://provider.example"
	if _, err := oauth.New(oauthtest.FakeProvider{}, base); err != nil {
		t.Fatalf("acceptance: New with issuer should succeed, got %v", err)
	}
}
func TestNew_clonesScopes(t *testing.T) {
	scopes := []string{"email", "profile"}
	c, err := oauth.New(oauthtest.FakeProvider{}, oauth.Config{
		ClientID:    oauthtest.ClientID,
		RedirectURL: "https://app.example/cb",
		Scopes:      scopes,
		Provider:    oauth.Google(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Mutate the caller's slice AFTER construction.
	scopes[0] = "admin"
	req, err := c.AuthCodeURL()
	if err != nil {
		t.Fatalf("AuthCodeURL: %v", err)
	}
	u, _ := url.Parse(req.URL)
	if got := u.Query().Get("scope"); got != "email profile" {
		t.Fatalf("scope = %q, want %q", got, "email profile")
	}
}
func TestNew_oauth2ProviderValid(t *testing.T) {
	// GitHub/Discord are valid even without issuer/JWKS (they supply userinfo).
	for _, p := range []oauth.Provider{oauth.GitHub(), oauth.Discord()} {
		if _, err := oauth.New(oauthtest.FakeProvider{}, oauth.Config{
			ClientID: "x", RedirectURL: "https://app.example/cb", Provider: p, Scopes: []string{"identify"},
		}); err != nil {
			t.Errorf("OAuth2 preset rejected: %v", err)
		}
	}
}
func TestNew_providerWithNoIdentitySourceRejected(t *testing.T) {
	// Well-formed https endpoints but neither issuer/JWKS nor userinfo: the
	// rejection must come from the identity-source check, not from URL
	// validation. Using invalid URLs would fail on URL parsing and pass the
	// test for the wrong reason.
	_, err := oauth.New(oauthtest.FakeProvider{}, oauth.Config{
		ClientID: "x", RedirectURL: "https://app.example/cb",
		Provider: oauth.Provider{
			AuthURL:  "https://provider.example/auth",
			TokenURL: "https://provider.example/token",
		},
	})
	if err == nil {
		t.Error("expected rejection of a provider with no identity source")
	} else if !strings.Contains(err.Error(), "JWKS") || !strings.Contains(err.Error(), "userinfo") {
		t.Fatalf("rejection must name the missing identity source (JWKS or userinfo), got %v", err)
	}
}

// TestConfig_ClientSecretAndFuncRejected pins the mutual exclusion of
// ClientSecret and ClientSecretFunc. The fragment in the error must
// name both fields so a regression that silently preferred one (and
// ignored the other) is visible in the failure text.
func TestConfig_ClientSecretAndFuncRejected(t *testing.T) {
	t.Parallel()
	_, err := oauth.New(oauthtest.FakeProvider{}, oauth.Config{
		ClientID:     oauthtest.ClientID,
		ClientSecret: "static",
		ClientSecretFunc: func(context.Context) (string, error) {
			return "dyn", nil
		},
		RedirectURL: "https://app.example.com/cb",
		Provider:    oauth.Apple(),
	})
	if err == nil {
		t.Fatal("expected rejection of a Config that sets both ClientSecret and ClientSecretFunc")
	}
	if !errors.Is(err, oauth.ErrInvalidConfig) {
		t.Fatalf("rejection must wrap ErrInvalidConfig, got %v", err)
	}
	if !strings.Contains(err.Error(), "ClientSecret and ClientSecretFunc") {
		t.Fatalf("rejection must name both fields, got %v", err)
	}
}

// TestNew_rejectsEveryMalformedEndpoint walks the branches of the config
// validation that the sub-package tests reach only through their own
// packages: an empty token URL, a plain-http endpoint and a fragment on the
// authorization URL each come back as ErrInvalidConfig.
func TestNew_rejectsEveryMalformedEndpoint(t *testing.T) {
	base := func() oauth.Config {
		return oauth.Config{
			ClientID:    "x",
			RedirectURL: "https://app.example/cb",
			Provider: oauth.Provider{
				AuthURL:     "https://idp.example/auth",
				TokenURL:    "https://idp.example/token",
				UserInfoURL: "https://idp.example/me",
			},
		}
	}
	cases := map[string]func(*oauth.Config){
		"empty token URL":      func(c *oauth.Config) { c.Provider.TokenURL = "" },
		"plain http endpoint":  func(c *oauth.Config) { c.Provider.UserInfoURL = "http://idp.example/me" },
		"fragment on auth URL": func(c *oauth.Config) { c.Provider.AuthURL += "#frag" },
	}
	for name, mutate := range cases {
		cfg := base()
		mutate(&cfg)
		if _, err := oauth.New(oauthtest.FakeProvider{}, cfg); !errors.Is(err, oauth.ErrInvalidConfig) {
			t.Errorf("%s: err = %v, want ErrInvalidConfig", name, err)
		}
	}
}

// TestPresets_publishTheirEndpoints pins the shape of the presets that the
// fixture tests in presets_*_test.go cover against captured provider documents.
func TestPresets_publishTheirEndpoints(t *testing.T) {
	const tenant = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"
	ms, err := oauth.Microsoft(tenant)
	if err != nil {
		t.Fatalf("Microsoft(%q): %v", tenant, err)
	}
	if ms.Issuer != "https://login.microsoftonline.com/"+tenant+"/v2.0" {
		t.Errorf("Microsoft issuer = %q", ms.Issuer)
	}
	if _, err := oauth.Microsoft("contoso.onmicrosoft.com"); err == nil {
		t.Error("Microsoft must refuse a domain tenant")
	}
	if v := oauth.Vercel(); v.Issuer != "https://vercel.com" || len(v.AuthMethods) != 2 {
		t.Errorf("Vercel preset drifted: %+v", v)
	}
	if !oauth.AzureMultiTenantIssuer()("https://login.microsoftonline.com/" + tenant + "/v2.0") {
		t.Error("AzureMultiTenantIssuer must accept a tenant-scoped v2.0 issuer")
	}
}

// TestFacade_wrapsTheSubPackages drives the thin public wrappers Discover,
// UserInfo and AppleClientSecret once each so this package's own coverage
// measures them; the behaviour behind them is tested in the sub-package that
// owns it.
func TestFacade_wrapsTheSubPackages(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration") {
			fmt.Fprintf(w, `{"issuer":%q,"authorization_endpoint":%q,"token_endpoint":%q,"jwks_uri":%q}`,
				srv.URL, srv.URL+"/auth", srv.URL+"/token", srv.URL+"/jwks")
			return
		}
		_, _ = w.Write([]byte(`{"id":42,"login":"octocat"}`))
	}))
	defer srv.Close()

	p, err := oauth.Discover(context.Background(), srv.URL, nil)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if p.TokenURL != srv.URL+"/token" {
		t.Errorf("TokenURL = %q", p.TokenURL)
	}
	if _, err := oauth.Discover(context.Background(), srv.URL+"/other", nil); !errors.Is(err, oauth.ErrDiscovery) {
		t.Errorf("Discover of a wrong issuer: err = %v, want ErrDiscovery", err)
	}

	info, err := oauthtest.OAuth2Client(t, srv.URL).UserInfo(context.Background(), "tok")
	if err != nil || info["login"] != "octocat" {
		t.Errorf("UserInfo = %v, %v", info, err)
	}

	if _, err := oauth.AppleClientSecret("short", "short", "client", []byte("not a key")); !errors.Is(err, oauth.ErrInvalidConfig) {
		t.Errorf("AppleClientSecret with bad input: err = %v, want ErrInvalidConfig", err)
	}
}
