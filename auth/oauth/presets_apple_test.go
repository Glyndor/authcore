package oauth_test

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth"
	"github.com/Glyndor/authcore/auth/oauth/internal/oauthtest"
)

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
	want := oauth.Apple()
	routes := map[string][]byte{
		"https://appleid.apple.com/.well-known/openid-configuration": readFixture(t, "apple-discovery.json"),
	}
	got, err := oauth.Discover(context.Background(),
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
	c, err := oauth.New(oauthtest.FakeProvider{}, oauth.Config{
		ClientID:    appleTestClientID,
		RedirectURL: "https://app.example.com/auth/apple/callback",
		Provider:    oauth.Apple(),
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
	c, err := oauth.New(oauthtest.FakeProvider{}, oauth.Config{
		ClientID:    appleTestClientID,
		RedirectURL: "https://app.example.com/auth/apple/callback",
		Provider:    oauth.Apple(),
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
