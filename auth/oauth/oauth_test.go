package oauth_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	gjwt "github.com/golang-jwt/jwt/v5"

	"github.com/Glyndor/authcore/auth/oauth"
	"github.com/Glyndor/authcore/auth/oauth/internal/oauthtest"
)

// ---- AuthCodeURL ------------------------------------------------------------

func TestVerifyIDToken_valid(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := oauthtest.JWKSServer(t, &key.PublicKey)
	defer srv.Close()
	c := oauthtest.NewClient(t, srv)

	tok := oauthtest.SignIDToken(t, key, oauthtest.KID, oauthtest.ValidClaims(srv.URL, "nonce-xyz"))
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
	srv := oauthtest.JWKSServer(t, &key.PublicKey)
	defer srv.Close()
	c := oauthtest.NewClient(t, srv)
	ctx := context.Background()

	t.Run("wrong nonce", func(t *testing.T) {
		tok := oauthtest.SignIDToken(t, key, oauthtest.KID, oauthtest.ValidClaims(srv.URL, "right"))
		if _, err := c.VerifyIDToken(ctx, tok, "wrong"); err == nil {
			t.Error("expected rejection on nonce mismatch")
		}
	})
	t.Run("empty nonce supplied", func(t *testing.T) {
		tok := oauthtest.SignIDToken(t, key, oauthtest.KID, oauthtest.ValidClaims(srv.URL, ""))
		if _, err := c.VerifyIDToken(ctx, tok, ""); err == nil {
			t.Error("expected rejection when no nonce is supplied")
		}
	})
	t.Run("wrong issuer", func(t *testing.T) {
		cl := oauthtest.ValidClaims("https://evil.example", "n")
		tok := oauthtest.SignIDToken(t, key, oauthtest.KID, cl)
		if _, err := c.VerifyIDToken(ctx, tok, "n"); err == nil {
			t.Error("expected rejection on issuer mismatch")
		}
	})
	t.Run("wrong audience", func(t *testing.T) {
		cl := oauthtest.ValidClaims(srv.URL, "n")
		cl["aud"] = "someone-else"
		tok := oauthtest.SignIDToken(t, key, oauthtest.KID, cl)
		if _, err := c.VerifyIDToken(ctx, tok, "n"); err == nil {
			t.Error("expected rejection on audience mismatch")
		}
	})
	t.Run("expired", func(t *testing.T) {
		cl := oauthtest.ValidClaims(srv.URL, "n")
		cl["exp"] = time.Now().Add(-time.Hour).Unix()
		tok := oauthtest.SignIDToken(t, key, oauthtest.KID, cl)
		if _, err := c.VerifyIDToken(ctx, tok, "n"); err == nil {
			t.Error("expected rejection on expired token")
		}
	})
	t.Run("wrong signing key", func(t *testing.T) {
		tok := oauthtest.SignIDToken(t, other, oauthtest.KID, oauthtest.ValidClaims(srv.URL, "n"))
		if _, err := c.VerifyIDToken(ctx, tok, "n"); err == nil {
			t.Error("expected rejection when signed by an unlisted key")
		}
	})
	t.Run("hmac alg-confusion", func(t *testing.T) {
		// A token signed with HS256 must be refused (asymmetric algs only).
		hs := gjwt.NewWithClaims(gjwt.SigningMethodHS256, oauthtest.ValidClaims(srv.URL, "n"))
		hs.Header["kid"] = oauthtest.KID
		s, _ := hs.SignedString([]byte("secret"))
		if _, err := c.VerifyIDToken(ctx, s, "n"); err == nil {
			t.Error("expected rejection of an HS256 token")
		}
	})
	t.Run("unknown kid", func(t *testing.T) {
		tok := oauthtest.SignIDToken(t, key, "no-such-kid", oauthtest.ValidClaims(srv.URL, "n"))
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
	c := oauthtest.NewClient(t, srv)

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
			// Return a valid JSON object so the rejection must come from the
			// status check, not from decoding an empty body. An empty body
			// would also fail decoding and pass the assertion for the wrong
			// reason.
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"bad"}`))
		}))
		defer srv.Close()
		if _, err := oauthtest.NewClient(t, srv).Exchange(context.Background(), "c", "v"); err == nil {
			t.Error("expected ErrExchange on 400")
		}
	})
	t.Run("no id_token", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"access_token":"at"}`))
		}))
		defer srv.Close()
		if _, err := oauthtest.NewClient(t, srv).Exchange(context.Background(), "c", "v"); err == nil {
			t.Error("expected ErrNoIDToken")
		}
	})
}

func TestName(t *testing.T) {
	c, _ := oauth.New(oauthtest.FakeProvider{}, oauth.Config{ClientID: "x", RedirectURL: "https://app.example/cb", Provider: oauth.Google()})
	if c.Name() != "oauth" {
		t.Errorf("Name() = %q, want oauth", c.Name())
	}
}

func TestVerifyIDToken_rejectsNonOIDCProvider(t *testing.T) {
	// A plain-OAuth2 client (UserInfoURL only) has nothing to verify an ID
	// token against; VerifyIDToken must refuse the call rather than skip the
	// iss check silently.
	c := oauthtest.OAuth2Client(t, "https://provider.example/userinfo")
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

func TestUserInfo_noURLConfigured(t *testing.T) {
	key := oauthtest.MustRSA(t)
	srv := oauthtest.JWKSServer(t, &key.PublicKey)
	defer srv.Close()
	// An OIDC client has no UserInfoURL.
	_, err := oauthtest.NewClient(t, srv).UserInfo(context.Background(), "x")
	if !errors.Is(err, oauth.ErrNoUserInfo) {
		t.Fatalf("expected ErrNoUserInfo on an OIDC client, got %v", err)
	}
}
