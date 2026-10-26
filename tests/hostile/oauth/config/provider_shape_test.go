package config_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth"
	"github.com/Glyndor/authcore/tests/hostile/oauth/hostiletest"
)

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func serving(body string) *http.Client {
	return &http.Client{Transport: roundTrip(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}, nil
	})}
}

func baseConfig() oauth.Config {
	return oauth.Config{
		ClientID:    hostiletest.ClientID,
		RedirectURL: "https://app.example/cb",
		Provider: oauth.Provider{
			AuthURL:     "https://idp.example/auth",
			TokenURL:    "https://idp.example/token",
			UserInfoURL: "https://idp.example/me",
		},
	}
}

func TestNewAnnouncesItselfThroughTheProvidersLogger(t *testing.T) {
	var logs hostiletest.CaptureLogger
	if _, err := oauth.New(hostiletest.SilentProvider{Log: &logs}, baseConfig()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "oauth: module initialised") {
		t.Fatalf("logs = %q, want the oauth initialisation line", logs.String())
	}
}

func TestNewRefusesAnEmptyAuthorizationEndpoint(t *testing.T) {
	for _, auth := range []string{"", "   "} {
		cfg := baseConfig()
		cfg.Provider.AuthURL = auth
		_, err := oauth.New(hostiletest.SilentProvider{}, cfg)
		if !errors.Is(err, oauth.ErrInvalidConfig) || !strings.Contains(err.Error(), "auth URL must not be empty") {
			t.Errorf("AuthURL %q: err = %v, want ErrInvalidConfig naming the auth URL", auth, err)
		}
	}
}

func TestADefaultScopeListOfOneIsHonoured(t *testing.T) {
	c := hostiletest.UserinfoClient(t, "https://idp.example/me", func(cfg *oauth.Config) {
		cfg.Scopes = nil
		cfg.Provider.DefaultScopes = []string{"read:user"}
	})
	req, err := c.AuthCodeURL()
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(req.URL)
	if got := u.Query().Get("scope"); got != "read:user" {
		t.Fatalf("scope = %q, want the provider's single default scope", got)
	}
}

func TestDiscoverAdmitsInternalEndpointsOnlyWhenAsked(t *testing.T) {
	const issuer = "https://provider.example"
	doc := `{"issuer":"` + issuer + `","authorization_endpoint":"https://10.0.0.5/auth",` +
		`"token_endpoint":"https://10.0.0.5/token","jwks_uri":"https://10.0.0.5/jwks"}`
	if _, err := oauth.Discover(context.Background(), issuer, serving(doc)); !errors.Is(err, oauth.ErrDiscovery) {
		t.Fatalf("an internal endpoint must be refused by default, got %v", err)
	}
	p, err := oauth.Discover(context.Background(), issuer, serving(doc), oauth.AllowPrivateNetwork())
	if err != nil || p.TokenURL != "https://10.0.0.5/token" {
		t.Fatalf("AllowPrivateNetwork must admit them: %+v, %v", p, err)
	}
}

// What makes a provider OIDC: a JWKS plus an issuer check, fixed or by
// predicate. A fixed issuer without a JWKS is a plain OAuth2 provider.
func TestIDTokenIsRequiredOnlyFromAnOIDCProvider(t *testing.T) {
	srv := hostiletest.Serve(t, hostiletest.StaticBody([]byte(`{"access_token":"at","token_type":"Bearer"}`)))
	validatorOnly := hostiletest.TokenClient(t, srv.URL+"/token", func(c *oauth.Config) {
		c.Provider.Issuer = ""
		c.IssuerValidator = func(string) bool { return true }
	})
	if _, err := validatorOnly.Exchange(hostiletest.Ctx(t), "code", "verifier"); !errors.Is(err, oauth.ErrNoIDToken) {
		t.Fatalf("a JWKS with an issuer predicate is OIDC and needs an ID token, got %v", err)
	}
	issuerNoJWKS := hostiletest.UserinfoClient(t, "https://idp.example/me", func(c *oauth.Config) {
		c.Provider.TokenURL = srv.URL + "/token"
		c.Provider.Issuer = hostiletest.Issuer
	})
	if _, err := issuerNoJWKS.Exchange(hostiletest.Ctx(t), "code", "verifier"); err != nil {
		t.Fatalf("an issuer without a JWKS is plain OAuth2 and needs no ID token, got %v", err)
	}
	_, err := issuerNoJWKS.VerifyIDToken(hostiletest.Ctx(t), "a.b.c", hostiletest.Nonce)
	if !errors.Is(err, oauth.ErrIDTokenInvalid) || !strings.Contains(err.Error(), "not configured for OIDC") {
		t.Fatalf("VerifyIDToken on a plain OAuth2 provider: %v", err)
	}
}

func TestAnIssuerPredicateOnTheConfigDecidesWhichIssuersAreTrusted(t *testing.T) {
	jwks := hostiletest.Serve(t, hostiletest.StaticBody(hostiletest.StdJWKS(t)))
	tok := hostiletest.SignA(t, hostiletest.Claims(hostiletest.Nonce, nil))
	for _, accept := range []bool{true, false} {
		c := hostiletest.OIDCClient(t, jwks.URL, func(cfg *oauth.Config) {
			cfg.Provider.Issuer = ""
			cfg.IssuerValidator = func(iss string) bool { return accept && iss == hostiletest.Issuer }
		})
		claims, err := hostiletest.Verify(t, c, tok)
		if accept && err != nil {
			t.Errorf("a predicate that accepts the issuer must verify the token: %v", err)
		}
		if !accept {
			hostiletest.MustRejectToken(t, claims, err)
		}
	}
}
