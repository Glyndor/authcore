package oauth_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	gjwt "github.com/golang-jwt/jwt/v5"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/oauth"
)

// ---- test infrastructure ----------------------------------------------------

type fakeProvider struct{}

func (fakeProvider) Config() authcore.Config { return authcore.DefaultConfig() }
func (fakeProvider) Logger() authcore.Logger { return silentLogger{} }
func (fakeProvider) Keys() authcore.Keys     { return nil }

type silentLogger struct{}

func (silentLogger) Debug(string, ...any) {}
func (silentLogger) Info(string, ...any)  {}
func (silentLogger) Warn(string, ...any)  {}
func (silentLogger) Error(string, ...any) {}

const (
	testClientID = "client-123"
	testKID      = "test-key-1"
)

// jwksServer serves a JWKS document for pubkey under testKID.
func jwksServer(t *testing.T, pub *rsa.PublicKey) *httptest.Server {
	t.Helper()
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	doc := fmt.Sprintf(`{"keys":[{"kty":"RSA","kid":%q,"n":%q,"e":%q}]}`, testKID, n, e)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(doc))
	}))
}

func signIDToken(t *testing.T, key *rsa.PrivateKey, kid string, claims gjwt.MapClaims) string {
	t.Helper()
	tok := gjwt.NewWithClaims(gjwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign id token: %v", err)
	}
	return s
}

func validClaims(issuer, nonce string) gjwt.MapClaims {
	return gjwt.MapClaims{
		"iss":            issuer,
		"aud":            testClientID,
		"sub":            "user-abc",
		"email":          "a@example.com",
		"email_verified": true,
		"nonce":          nonce,
		"exp":            time.Now().Add(time.Hour).Unix(),
		"iat":            time.Now().Add(-time.Minute).Unix(),
	}
}

// newClient builds a client whose Issuer/JWKS point at srv.
func newClient(t *testing.T, srv *httptest.Server) *oauth.Client {
	t.Helper()
	c, err := oauth.New(fakeProvider{}, oauth.Config{
		ClientID:    testClientID,
		RedirectURL: "https://app.example.com/cb",
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

// ---- AuthCodeURL ------------------------------------------------------------

func TestAuthCodeURL_hasPKCEAndState(t *testing.T) {
	c, _ := oauth.New(fakeProvider{}, oauth.Config{
		ClientID: testClientID, RedirectURL: "https://app/cb", Provider: oauth.Google(),
	})
	req, err := c.AuthCodeURL()
	if err != nil {
		t.Fatalf("AuthCodeURL: %v", err)
	}
	if req.State == "" || req.Nonce == "" || req.Verifier == "" {
		t.Fatal("state/nonce/verifier must be set")
	}
	u, _ := url.Parse(req.URL)
	q := u.Query()
	for k, want := range map[string]string{
		"response_type":         "code",
		"client_id":             testClientID,
		"code_challenge_method": "S256",
		"state":                 req.State,
		"nonce":                 req.Nonce,
	} {
		if q.Get(k) != want {
			t.Errorf("query %q = %q, want %q", k, q.Get(k), want)
		}
	}
	if !strings.Contains(q.Get("scope"), "openid") {
		t.Errorf("scope %q missing openid", q.Get("scope"))
	}
	if q.Get("code_challenge") == req.Verifier {
		t.Error("challenge must be the hash of the verifier, not the verifier itself")
	}
}

func TestAuthCodeURL_independentPerCall(t *testing.T) {
	c, _ := oauth.New(fakeProvider{}, oauth.Config{ClientID: "x", RedirectURL: "https://app.example/cb", Provider: oauth.Google()})
	a, _ := c.AuthCodeURL()
	b, _ := c.AuthCodeURL()
	if a.State == b.State || a.Nonce == b.Nonce || a.Verifier == b.Verifier {
		t.Error("each AuthCodeURL must use fresh secrets")
	}
}

// ---- New validation ---------------------------------------------------------

func TestNew_invalidConfigRejected(t *testing.T) {
	cases := map[string]oauth.Config{
		"no client id": {RedirectURL: "https://app.example/cb", Provider: oauth.Google()},
		"no redirect":  {ClientID: "x", Provider: oauth.Google()},
		"no provider":  {ClientID: "x", RedirectURL: "https://app.example/cb"},
	}
	for name, cfg := range cases {
		if _, err := oauth.New(fakeProvider{}, cfg); err == nil {
			t.Errorf("%s: expected ErrInvalidConfig", name)
		}
	}
}

// ---- VerifyIDToken (the security-critical path) -----------------------------

func TestVerifyIDToken_valid(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := jwksServer(t, &key.PublicKey)
	defer srv.Close()
	c := newClient(t, srv)

	tok := signIDToken(t, key, testKID, validClaims(srv.URL, "nonce-xyz"))
	claims, err := c.VerifyIDToken(context.Background(), tok, "nonce-xyz")
	if err != nil {
		t.Fatalf("VerifyIDToken: %v", err)
	}
	if claims.Subject != "user-abc" {
		t.Errorf("Subject = %q, want user-abc", claims.Subject)
	}
	if claims.Email != "a@example.com" || !claims.EmailVerified {
		t.Errorf("email claims not parsed: %+v", claims)
	}
}

func TestVerifyIDToken_rejections(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := jwksServer(t, &key.PublicKey)
	defer srv.Close()
	c := newClient(t, srv)
	ctx := context.Background()

	t.Run("wrong nonce", func(t *testing.T) {
		tok := signIDToken(t, key, testKID, validClaims(srv.URL, "right"))
		if _, err := c.VerifyIDToken(ctx, tok, "wrong"); err == nil {
			t.Error("expected rejection on nonce mismatch")
		}
	})
	t.Run("empty nonce supplied", func(t *testing.T) {
		tok := signIDToken(t, key, testKID, validClaims(srv.URL, ""))
		if _, err := c.VerifyIDToken(ctx, tok, ""); err == nil {
			t.Error("expected rejection when no nonce is supplied")
		}
	})
	t.Run("wrong issuer", func(t *testing.T) {
		cl := validClaims("https://evil.example", "n")
		tok := signIDToken(t, key, testKID, cl)
		if _, err := c.VerifyIDToken(ctx, tok, "n"); err == nil {
			t.Error("expected rejection on issuer mismatch")
		}
	})
	t.Run("wrong audience", func(t *testing.T) {
		cl := validClaims(srv.URL, "n")
		cl["aud"] = "someone-else"
		tok := signIDToken(t, key, testKID, cl)
		if _, err := c.VerifyIDToken(ctx, tok, "n"); err == nil {
			t.Error("expected rejection on audience mismatch")
		}
	})
	t.Run("expired", func(t *testing.T) {
		cl := validClaims(srv.URL, "n")
		cl["exp"] = time.Now().Add(-time.Hour).Unix()
		tok := signIDToken(t, key, testKID, cl)
		if _, err := c.VerifyIDToken(ctx, tok, "n"); err == nil {
			t.Error("expected rejection on expired token")
		}
	})
	t.Run("wrong signing key", func(t *testing.T) {
		tok := signIDToken(t, other, testKID, validClaims(srv.URL, "n"))
		if _, err := c.VerifyIDToken(ctx, tok, "n"); err == nil {
			t.Error("expected rejection when signed by an unlisted key")
		}
	})
	t.Run("hmac alg-confusion", func(t *testing.T) {
		// A token signed with HS256 must be refused (asymmetric algs only).
		hs := gjwt.NewWithClaims(gjwt.SigningMethodHS256, validClaims(srv.URL, "n"))
		hs.Header["kid"] = testKID
		s, _ := hs.SignedString([]byte("secret"))
		if _, err := c.VerifyIDToken(ctx, s, "n"); err == nil {
			t.Error("expected rejection of an HS256 token")
		}
	})
	t.Run("unknown kid", func(t *testing.T) {
		tok := signIDToken(t, key, "no-such-kid", validClaims(srv.URL, "n"))
		if _, err := c.VerifyIDToken(ctx, tok, "n"); err == nil {
			t.Error("expected rejection for an unknown kid")
		}
	})
}

// ---- Exchange ---------------------------------------------------------------

func TestExchange_success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.FormValue("grant_type") != "authorization_code" || r.FormValue("code_verifier") == "" {
			t.Errorf("token request missing grant_type/code_verifier: %v", r.Form)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "at", "id_token": "idt", "token_type": "Bearer", "expires_in": 3600,
		})
	}))
	defer srv.Close()
	c := newClient(t, srv)

	tok, err := c.Exchange(context.Background(), "the-code", "the-verifier")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if tok.AccessToken != "at" || tok.IDToken != "idt" {
		t.Errorf("unexpected tokens: %+v", tok)
	}
}

func TestExchange_errors(t *testing.T) {
	t.Run("non-2xx", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
		}))
		defer srv.Close()
		if _, err := newClient(t, srv).Exchange(context.Background(), "c", "v"); err == nil {
			t.Error("expected ErrExchange on 400")
		}
	})
	t.Run("no id_token", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"access_token":"at"}`))
		}))
		defer srv.Close()
		if _, err := newClient(t, srv).Exchange(context.Background(), "c", "v"); err == nil {
			t.Error("expected ErrNoIDToken")
		}
	})
}

func TestName(t *testing.T) {
	c, _ := oauth.New(fakeProvider{}, oauth.Config{ClientID: "x", RedirectURL: "https://app.example/cb", Provider: oauth.Google()})
	if c.Name() != "oauth" {
		t.Errorf("Name() = %q, want oauth", c.Name())
	}
}
