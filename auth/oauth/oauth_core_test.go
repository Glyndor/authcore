package oauth_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth"
)

// ---- Section 1: unified isOIDC predicate ----------------------------------

func TestNew_rejectsJWKSWithoutIssuerCheck(t *testing.T) {
	// JWKSURL + UserInfoURL + empty Issuer + nil IssuerValidator was accepted
	// before validateConfig changed: the half-configured check was gated on
	// !oauth2, so UserInfoURL hid the missing iss check.
	base := oauth.Config{
		ClientID:    testClientID,
		RedirectURL: "https://app.example/cb",
		Scopes:      []string{"read:user"},
		Provider: oauth.Provider{
			AuthURL:     "https://provider.example/auth",
			TokenURL:    "https://provider.example/token",
			JWKSURL:     "https://provider.example/jwks",
			UserInfoURL: "https://provider.example/userinfo",
		},
	}
	if _, err := oauth.New(fakeProvider{}, base); !errors.Is(err, oauth.ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig, got %v", err)
	}
	// Acceptance pair: the same config with an issuer must construct.
	base.Provider.Issuer = "https://provider.example"
	if _, err := oauth.New(fakeProvider{}, base); err != nil {
		t.Fatalf("acceptance: New with issuer should succeed, got %v", err)
	}
}

func TestVerifyIDToken_rejectsNonOIDCProvider(t *testing.T) {
	// A plain-OAuth2 client (UserInfoURL only) has nothing to verify an ID
	// token against; VerifyIDToken must refuse the call rather than skip the
	// iss check silently.
	c := oauth2Client(t, "https://provider.example/userinfo")
	_, err := c.VerifyIDToken(context.Background(), "anything", "nonce")
	if !errors.Is(err, oauth.ErrIDTokenInvalid) {
		t.Fatalf("expected ErrIDTokenInvalid, got %v", err)
	}
	// The sentinel alone does not pin this down: a malformed token, or a JWKS
	// that yields no key, reaches the same sentinel by another route. Require
	// the refusal to name the configuration, so removing the check is visible
	// here.
	if !strings.Contains(err.Error(), "not configured for OIDC") {
		t.Fatalf("error does not name the rule that refused the call: %v", err)
	}
}

func TestExchange_requiresIDTokenWithIssuerValidator(t *testing.T) {
	// A token response without id_token must fail for an OIDC client whose
	// issuer check is the validator (no fixed Provider.Issuer), since the
	// single isOIDC predicate counts that case as OIDC.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":"Bearer"}`))
	}))
	defer srv.Close()
	c, err := oauth.New(fakeProvider{}, oauth.Config{
		ClientID:    testClientID,
		RedirectURL: "https://app.example/cb",
		Scopes:      []string{"openid"},
		Provider: oauth.Provider{
			AuthURL:  srv.URL + "/auth",
			TokenURL: srv.URL + "/token",
			JWKSURL:  srv.URL,
		},
		IssuerValidator: func(string) bool { return true },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := c.Exchange(context.Background(), "c", "v"); !errors.Is(err, oauth.ErrNoIDToken) {
		t.Fatalf("expected ErrNoIDToken, got %v", err)
	}
}

// ---- Section 2: ID token audiences and iat ---------------------------------

func TestVerifyIDToken_rejectsExtraAudience(t *testing.T) {
	key := mustRSA(t)
	srv := jwksServer(t, &key.PublicKey)
	defer srv.Close()
	c := newClient(t, srv)

	cl := validClaims(srv.URL, "n")
	cl["aud"] = []string{testClientID, "other"}
	cl["azp"] = testClientID
	tok := signIDToken(t, key, testKID, cl)
	if _, err := c.VerifyIDToken(context.Background(), tok, "n"); !errors.Is(err, oauth.ErrIDTokenInvalid) {
		t.Fatalf("expected ErrIDTokenInvalid, got %v", err)
	}
	// Acceptance pair: a token whose only audience is the client id verifies.
	cl["aud"] = []string{testClientID}
	delete(cl, "azp")
	tok = signIDToken(t, key, testKID, cl)
	if _, err := c.VerifyIDToken(context.Background(), tok, "n"); err != nil {
		t.Fatalf("acceptance: VerifyIDToken, got %v", err)
	}
}

func TestVerifyIDToken_requiresIssuedAt(t *testing.T) {
	key := mustRSA(t)
	srv := jwksServer(t, &key.PublicKey)
	defer srv.Close()
	c := newClient(t, srv)

	// validClaims already sets iat; remove it for the rejection case.
	cl := validClaims(srv.URL, "n")
	delete(cl, "iat")
	tok := signIDToken(t, key, testKID, cl)
	if _, err := c.VerifyIDToken(context.Background(), tok, "n"); !errors.Is(err, oauth.ErrIDTokenInvalid) {
		t.Fatalf("expected ErrIDTokenInvalid on missing iat, got %v", err)
	}
	// Acceptance pair: the same token with iat set verifies.
	cl["iat"] = validClaims(srv.URL, "n")["iat"]
	tok = signIDToken(t, key, testKID, cl)
	if _, err := c.VerifyIDToken(context.Background(), tok, "n"); err != nil {
		t.Fatalf("acceptance: VerifyIDToken with iat, got %v", err)
	}
}

// ---- Section 3: provider error bodies and empty inputs --------------------

// newOIDCClientWithTokenServer builds an OIDC client whose TokenURL points at
// srv and whose AuthURL/JWKSURL/UserInfoURL all point at the same server so
// config validation succeeds.
func newOIDCClientWithTokenServer(t *testing.T, srv *httptest.Server) *oauth.Client {
	t.Helper()
	c, err := oauth.New(fakeProvider{}, oauth.Config{
		ClientID:    testClientID,
		RedirectURL: "https://app.example/cb",
		Scopes:      []string{"openid"},
		Provider: oauth.Provider{
			Issuer:   srv.URL,
			AuthURL:  srv.URL + "/auth",
			TokenURL: srv.URL + "/token",
			JWKSURL:  srv.URL,
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestExchange_rejectsErrorBodyWith200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"code expired"}`))
	}))
	defer srv.Close()
	c := newOIDCClientWithTokenServer(t, srv)

	tok, err := c.Exchange(context.Background(), "c", "v")
	if !errors.Is(err, oauth.ErrExchange) {
		t.Fatalf("expected ErrExchange, got %v", err)
	}
	if tok != nil {
		t.Fatalf("token must be nil, got %+v", tok)
	}
	if !strings.Contains(err.Error(), "invalid_grant") {
		t.Fatalf("error must include the provider code, got %v", err)
	}
	// Acceptance pair: a well-formed success response still parses.
	okSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":"Bearer","id_token":"idt"}`))
	}))
	defer okSrv.Close()
	okClient := newOIDCClientWithTokenServer(t, okSrv)
	got, err := okClient.Exchange(context.Background(), "c", "v")
	if err != nil {
		t.Fatalf("acceptance: Exchange, got %v", err)
	}
	if got.AccessToken != "at" || got.IDToken != "idt" {
		t.Fatalf("acceptance: unexpected tokens %+v", got)
	}
}

func TestExchange_rejectsEmptyAccessToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	c := newOIDCClientWithTokenServer(t, srv)

	if _, err := c.Exchange(context.Background(), "c", "v"); !errors.Is(err, oauth.ErrExchange) {
		t.Fatalf("expected ErrExchange on empty token body, got %v", err)
	}
}

func TestExchange_rejectsEmptyCode(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":"Bearer"}`))
	}))
	defer srv.Close()
	c := newOIDCClientWithTokenServer(t, srv)
	if _, err := c.Exchange(context.Background(), "", "v"); !errors.Is(err, oauth.ErrExchange) {
		t.Fatalf("expected ErrExchange on empty code, got %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Fatalf("token endpoint was hit %d times; an empty code must short-circuit", got)
	}
}

func TestExchange_rejectsEmptyVerifier(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":"Bearer"}`))
	}))
	defer srv.Close()
	c := newOIDCClientWithTokenServer(t, srv)
	if _, err := c.Exchange(context.Background(), "c", ""); !errors.Is(err, oauth.ErrExchange) {
		t.Fatalf("expected ErrExchange on empty verifier, got %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Fatalf("token endpoint was hit %d times; an empty verifier must short-circuit", got)
	}
}

func TestUserInfo_rejectsEmptyAccessToken(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = w.Write([]byte(`{"id":1}`))
	}))
	defer srv.Close()
	c := oauth2Client(t, srv.URL)
	if _, err := c.UserInfo(context.Background(), ""); !errors.Is(err, oauth.ErrUserInfo) {
		t.Fatalf("expected ErrUserInfo on empty token, got %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Fatalf("userinfo endpoint was hit %d times; an empty token must short-circuit", got)
	}
}

func TestUserInfo_rejectsNullBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`null`))
	}))
	defer srv.Close()
	c := oauth2Client(t, srv.URL)
	if _, err := c.UserInfo(context.Background(), "at"); !errors.Is(err, oauth.ErrUserInfo) {
		t.Fatalf("expected ErrUserInfo on null body, got %v", err)
	}
	// Acceptance pair: a real object returns the map.
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":1,"login":"octocat"}`))
	}))
	defer good.Close()
	got, err := oauth2Client(t, good.URL).UserInfo(context.Background(), "at")
	if err != nil {
		t.Fatalf("acceptance: UserInfo, got %v", err)
	}
	if got["login"] != "octocat" {
		t.Fatalf("acceptance: login = %v", got["login"])
	}
}

// ---- Section 4: numeric ids survive decoding -------------------------------

func TestUserInfo_preservesLargeNumericID(t *testing.T) {
	// 9007199254740993 is 2^53 + 1; json.Unmarshal into map[string]any would
	// collapse it onto the same float64 as 2^53 (9007199254740992). With
	// UseNumber they decode as distinct json.Number values.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":9007199254740993,"near":9007199254740992}`))
	}))
	defer srv.Close()
	c := oauth2Client(t, srv.URL)

	got, err := c.UserInfo(context.Background(), "at")
	if err != nil {
		t.Fatalf("UserInfo: %v", err)
	}
	idNum, ok := got["id"].(json.Number)
	if !ok {
		t.Fatalf("id must decode as json.Number, got %T", got["id"])
	}
	if got["id"] == got["near"] {
		t.Fatalf("large id collapsed onto neighbour: %v == %v", got["id"], got["near"])
	}
	if string(idNum) != "9007199254740993" {
		t.Fatalf("id = %q, want 9007199254740993", string(idNum))
	}
}

// ---- Section 5: scopes are not aliased to the caller's slice ---------------

func TestNew_clonesScopes(t *testing.T) {
	scopes := []string{"email", "profile"}
	c, err := oauth.New(fakeProvider{}, oauth.Config{
		ClientID:    testClientID,
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
