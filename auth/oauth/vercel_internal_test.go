package oauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

// TestPreset_VercelDiscoveryMatchesVercelPreset pins every URL the Vercel
// preset hardcodes against the document Vercel published at its OIDC
// discovery URL (captured 2026-09-27 in vercel-discovery.json). The
// comparison is byte-for-byte against Vercel(), not against literals, so
// a change on either side flips this test in the right direction.
//
// The test also asserts that every AuthMethod the preset advertises is
// present in the discovered document's token_endpoint_auth_methods_supported,
// since the method Exchange picks is read from that field; a regression that
// dropped "client_secret_basic" or "client_secret_post" would change how
// the secret is sent at runtime, and the discovery check is where it has
// to fail.
func TestPreset_VercelDiscoveryMatchesVercelPreset(t *testing.T) {
	t.Parallel()
	want := Vercel()
	routes := map[string][]byte{
		"https://vercel.com/.well-known/openid-configuration": readFixture(t, "vercel-discovery.json"),
	}
	got, err := Discover(context.Background(),
		"https://vercel.com", stubClient(routes))
	if err != nil {
		t.Fatalf("Discover(vercel): %v", err)
	}
	if got.Issuer != want.Issuer {
		t.Errorf("Issuer: got %q, want %q", got.Issuer, want.Issuer)
	}
	if got.AuthURL != want.AuthURL {
		t.Errorf("AuthURL: got %q, want %q", got.AuthURL, want.AuthURL)
	}
	if got.TokenURL != want.TokenURL {
		t.Errorf("TokenURL: got %q, want %q", got.TokenURL, want.TokenURL)
	}
	if got.JWKSURL != want.JWKSURL {
		t.Errorf("JWKSURL: got %q, want %q", got.JWKSURL, want.JWKSURL)
	}
	discovered := make(map[string]struct{}, len(got.AuthMethods))
	for _, m := range got.AuthMethods {
		discovered[strings.ToLower(m)] = struct{}{}
	}
	for _, m := range want.AuthMethods {
		if _, ok := discovered[strings.ToLower(m)]; !ok {
			t.Errorf("Vercel() advertises %q but the discovery document does not list it under token_endpoint_auth_methods_supported (got %v)",
				m, got.AuthMethods)
		}
	}
}

// TestAuthCodeURL_VercelScopeAndPKCE pins two surfaces together: the
// authorization URL must carry code_challenge_method=S256 (the only method
// Vercel advertises in code_challenge_methods_supported) and the scope
// must be the OIDC default "openid email profile" verbatim, since
// Provider.DefaultScopes is empty for Vercel.
func TestAuthCodeURL_VercelScopeAndPKCE(t *testing.T) {
	t.Parallel()
	c, err := New(appleFakeProvider{}, Config{
		ClientID:    "vercel-client-id",
		RedirectURL: "https://app.example.com/auth/vercel/callback",
		Provider:    Vercel(),
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
	if got := q.Get("code_challenge_method"); got != "S256" {
		t.Errorf("code_challenge_method = %q, want S256", got)
	}
	if got := q.Get("scope"); got != "openid email profile" {
		t.Errorf("scope = %q, want %q", got, "openid email profile")
	}
	if _, ok := q["code_challenge"]; !ok {
		t.Error("code_challenge is missing from the URL")
	}
}

// TestExchange_VercelBasicWinsOverPost pins the rule that when a provider
// advertises both client_secret_basic and client_secret_post, Exchange
// sends the secret in the Authorization header and leaves the form body
// without a client_secret field. The handler captures what arrived and
// asserts here; a regression that sent the secret in BOTH places, or that
// chose Post when both were advertised, would change the bytes on the
// wire and fail this test.
func TestExchange_VercelBasicWinsOverPost(t *testing.T) {
	t.Parallel()
	type captured struct {
		authorization string
		formSecret    string
	}
	var (
		got atomic.Pointer[captured]
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		got.Store(&captured{
			authorization: r.Header.Get("Authorization"),
			formSecret:    r.FormValue("client_secret"),
		})
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":"Bearer","id_token":"x"}`))
	}))
	defer srv.Close()

	p := Vercel()
	p.TokenURL = srv.URL
	c, err := New(appleFakeProvider{}, Config{
		ClientID:     "vercel-client-id",
		ClientSecret: "vercel-client-secret",
		RedirectURL:  "https://app.example.com/auth/vercel/callback",
		HTTPClient:   newLoopbackClient(t, srv),
		Provider:     p,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := c.Exchange(context.Background(), "code", "verifier"); err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	cap := got.Load()
	if cap == nil {
		t.Fatal("token endpoint saw no request")
	}
	const wantBasic = "Basic dmVyY2VsLWNsaWVudC1pZDp2ZXJjZWwtY2xpZW50LXNlY3JldA=="
	if cap.authorization != wantBasic {
		t.Errorf("Authorization header = %q, want %q (Basic client_secret must be sent when advertised alongside Post)",
			cap.authorization, wantBasic)
	}
	if cap.formSecret != "" {
		t.Errorf("client_secret form field = %q, want empty (Basic wins: the secret must not also appear in the form body)",
			cap.formSecret)
	}
}
