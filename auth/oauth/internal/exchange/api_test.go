package exchange_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/oauth"
	"github.com/Glyndor/authcore/auth/oauth/internal/oauthtest"
)

// ---- Section 1: unified isOIDC predicate ----------------------------------

func TestExchange_requiresIDTokenWithIssuerValidator(t *testing.T) {
	// A token response without id_token must fail for an OIDC client whose
	// issuer check is the validator (no fixed Provider.Issuer), since the
	// single isOIDC predicate counts that case as OIDC.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":"Bearer"}`))
	}))
	defer srv.Close()
	c, err := oauth.New(oauthtest.FakeProvider{}, oauth.Config{
		ClientID:    oauthtest.ClientID,
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

// ---- Section 3: provider error bodies and empty inputs --------------------

func TestExchange_rejectsErrorBodyWith200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"code expired"}`))
	}))
	defer srv.Close()
	c := oauthtest.NewTokenClient(t, srv)

	tok, err := c.Exchange(context.Background(), "auth-code", "pkce-verifier")
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
	okClient := oauthtest.NewTokenClient(t, okSrv)
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
	c := oauthtest.NewTokenClient(t, srv)

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
	c := oauthtest.NewTokenClient(t, srv)
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
	c := oauthtest.NewTokenClient(t, srv)
	if _, err := c.Exchange(context.Background(), "c", ""); !errors.Is(err, oauth.ErrExchange) {
		t.Fatalf("expected ErrExchange on empty verifier, got %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Fatalf("token endpoint was hit %d times; an empty verifier must short-circuit", got)
	}
}

// ---- Section 4: numeric ids survive decoding -------------------------------

// ---- Section 5: scopes are not aliased to the caller's slice ---------------

// The token endpoint can return HTTP 200 with an OAuth error body. A long
// error_description is capped, and the truncation mark must survive into the
// surface error: the cap is the reason the cap exists.
func TestExchange_longErrorDescriptionIsTruncated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// 600 'x' characters: well past the 512-byte cap.
		_, _ = fmt.Fprintf(w, `{"error":"invalid_grant","error_description":"%s"}`, strings.Repeat("x", 600))
	}))
	defer srv.Close()
	c := oauthtest.NewTokenClient(t, srv)

	_, err := c.Exchange(context.Background(), "auth-code", "pkce-verifier")
	if !errors.Is(err, oauth.ErrExchange) {
		t.Fatalf("expected ErrExchange, got %v", err)
	}
	// The truncated block plus the ellipsis marks: 512 'x' followed by "…".
	if !strings.Contains(err.Error(), strings.Repeat("x", 512)+"…") {
		t.Fatalf("error must surface the truncated description, got %v", err)
	}
	if !strings.Contains(err.Error(), "invalid_grant") {
		t.Fatalf("error must include the provider error code, got %v", err)
	}
}

// A 200 response that is well-formed but missing token_type is a malformed
// success: the access token by itself tells the caller nothing about how to
// present it.
func TestExchange_emptyTokenTypeRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":""}`))
	}))
	defer srv.Close()
	c := oauthtest.NewTokenClient(t, srv)

	_, err := c.Exchange(context.Background(), "c", "v")
	if !errors.Is(err, oauth.ErrExchange) {
		t.Fatalf("expected ErrExchange, got %v", err)
	}
	// Acceptance pair: a body with token_type set parses and returns the tokens.
	okSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":"Bearer","id_token":"idt"}`))
	}))
	defer okSrv.Close()
	got, err := oauthtest.NewTokenClient(t, okSrv).Exchange(context.Background(), "c", "v")
	if err != nil {
		t.Fatalf("acceptance: Exchange, got %v", err)
	}
	if got.TokenType != "Bearer" || got.AccessToken != "at" {
		t.Fatalf("acceptance: unexpected tokens %+v", got)
	}
}

// A 200 body that is not an object. The spec says the response is an object,
// so "null", "[…]", or a bare string is the endpoint speaking out of turn.
func TestExchange_nonObjectBodyRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`"a bare json string"`))
	}))
	defer srv.Close()
	c := oauthtest.NewTokenClient(t, srv)

	_, err := c.Exchange(context.Background(), "c", "v")
	if !errors.Is(err, oauth.ErrExchange) {
		t.Fatalf("expected ErrExchange, got %v", err)
	}
	if !strings.Contains(err.Error(), "decode") {
		t.Fatalf("error does not name the cause (want decode), got %v", err)
	}
}

func TestExchange_oauth2ReturnsTokensWithoutIDToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// A plain-OAuth2 provider returns no id_token.
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":"bearer"}`))
	}))
	defer srv.Close()

	c, err := oauth.New(oauthtest.FakeProvider{}, oauth.Config{
		ClientID:    oauthtest.ClientID,
		RedirectURL: "https://app.example/cb",
		Scopes:      []string{"read:user"},
		Provider: oauth.Provider{
			AuthURL:     srv.URL + "/auth",
			TokenURL:    srv.URL + "/token",
			UserInfoURL: srv.URL + "/userinfo",
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	tok, err := c.Exchange(context.Background(), "code", "verifier")
	if err != nil {
		t.Fatalf("OAuth2 exchange must succeed without an id_token, got %v", err)
	}
	if tok.AccessToken != "at" {
		t.Errorf("access token = %q, want at", tok.AccessToken)
	}
}

func TestExchange_contextDeadline(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(50 * time.Millisecond)
		_, _ = w.Write([]byte(`{"id_token":"x"}`))
	}))
	defer srv.Close()
	c := oauthtest.NewClient(t, srv)
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if _, err := c.Exchange(ctx, "c", "v"); err == nil {
		t.Error("expected a context-deadline error")
	}
}
