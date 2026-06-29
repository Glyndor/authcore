package oauth_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	gjwt "github.com/golang-jwt/jwt/v5"

	"github.com/Glyndor/authcore/auth/oauth"
)

// ---- OAuth2 (userinfo) path -------------------------------------------------

func oauth2Client(t *testing.T, userInfoURL string) *oauth.Client {
	t.Helper()
	c, err := oauth.New(fakeProvider{}, oauth.Config{
		ClientID:    testClientID,
		RedirectURL: "https://app.example.com/cb",
		Scopes:      []string{"read:user"},
		Provider: oauth.Provider{
			AuthURL:     "https://provider.example/auth",
			TokenURL:    "https://provider.example/token",
			UserInfoURL: userInfoURL,
		},
	})
	if err != nil {
		t.Fatalf("New (oauth2): %v", err)
	}
	return c
}

func TestUserInfo_success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer the-access-token" {
			t.Errorf("missing/!wrong bearer: %q", r.Header.Get("Authorization"))
		}
		_, _ = w.Write([]byte(`{"id":42,"login":"octocat"}`))
	}))
	defer srv.Close()

	info, err := oauth2Client(t, srv.URL).UserInfo(context.Background(), "the-access-token")
	if err != nil {
		t.Fatalf("UserInfo: %v", err)
	}
	if info["login"] != "octocat" {
		t.Errorf("login = %v, want octocat", info["login"])
	}
}

func TestUserInfo_noURLConfigured(t *testing.T) {
	key := mustRSA(t)
	srv := jwksServer(t, &key.PublicKey)
	defer srv.Close()
	// An OIDC client has no UserInfoURL.
	if _, err := newClient(t, srv).UserInfo(context.Background(), "x"); err == nil {
		t.Error("expected ErrNoUserInfo on an OIDC client")
	}
}

func TestUserInfo_non2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	if _, err := oauth2Client(t, srv.URL).UserInfo(context.Background(), "x"); err == nil {
		t.Error("expected an error on a non-2xx userinfo response")
	}
}

func TestNew_oauth2ProviderValid(t *testing.T) {
	// GitHub/Discord are valid even without issuer/JWKS (they supply userinfo).
	for _, p := range []oauth.Provider{oauth.GitHub(), oauth.Discord()} {
		if _, err := oauth.New(fakeProvider{}, oauth.Config{
			ClientID: "x", RedirectURL: "y", Provider: p, Scopes: []string{"identify"},
		}); err != nil {
			t.Errorf("OAuth2 preset rejected: %v", err)
		}
	}
}

func TestNew_providerWithNoIdentitySourceRejected(t *testing.T) {
	// Auth + token endpoints but neither issuer/JWKS nor userinfo.
	_, err := oauth.New(fakeProvider{}, oauth.Config{
		ClientID: "x", RedirectURL: "y",
		Provider: oauth.Provider{AuthURL: "a", TokenURL: "t"},
	})
	if err == nil {
		t.Error("expected rejection of a provider with no identity source")
	}
}

func mustRSA(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return k
}

// ---- EC (ES256) end-to-end --------------------------------------------------

func TestVerifyIDToken_ecKey(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// SEC1 uncompressed point: 0x04 || x(32) || y(32). Avoids the deprecated
	// raw X/Y coordinate accessors.
	raw, err := key.PublicKey.Bytes()
	if err != nil {
		t.Fatalf("public key bytes: %v", err)
	}
	x := base64.RawURLEncoding.EncodeToString(raw[1:33])
	y := base64.RawURLEncoding.EncodeToString(raw[33:65])
	doc := fmt.Sprintf(`{"keys":[{"kty":"EC","kid":%q,"crv":"P-256","x":%q,"y":%q}]}`, testKID, x, y)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(doc))
	}))
	defer srv.Close()
	c := newClient(t, srv)

	tok := gjwt.NewWithClaims(gjwt.SigningMethodES256, validClaims(srv.URL, "n"))
	tok.Header["kid"] = testKID
	signed, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign ES256: %v", err)
	}

	claims, err := c.VerifyIDToken(context.Background(), signed, "n")
	if err != nil {
		t.Fatalf("VerifyIDToken (EC): %v", err)
	}
	if claims.Subject != "user-abc" {
		t.Errorf("Subject = %q", claims.Subject)
	}
}

// ---- claim variants ---------------------------------------------------------

func TestVerifyIDToken_audArrayAndStringEmailVerified(t *testing.T) {
	key := mustRSA(t)
	srv := jwksServer(t, &key.PublicKey)
	defer srv.Close()
	c := newClient(t, srv)

	cl := validClaims(srv.URL, "n")
	cl["aud"] = []string{testClientID, "another"}
	cl["email_verified"] = "true" // some providers send a string
	tok := signIDToken(t, key, testKID, cl)

	claims, err := c.VerifyIDToken(context.Background(), tok, "n")
	if err != nil {
		t.Fatalf("VerifyIDToken: %v", err)
	}
	if len(claims.Audience) != 2 {
		t.Errorf("Audience = %v, want 2 entries", claims.Audience)
	}
	if !claims.EmailVerified {
		t.Error("string email_verified \"true\" not parsed as true")
	}
}

// ---- JWKS error paths -------------------------------------------------------

func TestVerifyIDToken_jwksNon200(t *testing.T) {
	key := mustRSA(t)
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer bad.Close()
	c := newClient(t, bad)
	tok := signIDToken(t, key, testKID, validClaims(bad.URL, "n"))
	if _, err := c.VerifyIDToken(context.Background(), tok, "n"); err == nil {
		t.Error("expected failure when JWKS endpoint returns 500")
	}
}

func TestVerifyIDToken_jwksEmpty(t *testing.T) {
	key := mustRSA(t)
	empty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer empty.Close()
	c := newClient(t, empty)
	tok := signIDToken(t, key, testKID, validClaims(empty.URL, "n"))
	if _, err := c.VerifyIDToken(context.Background(), tok, "n"); err == nil {
		t.Error("expected failure when JWKS has no usable keys")
	}
}

// ---- config / presets -------------------------------------------------------

func TestAuthCodeURL_defaultScopesIncludeOpenID(t *testing.T) {
	// No scopes set -> the OIDC default set (with openid) is used.
	c, _ := oauth.New(fakeProvider{}, oauth.Config{
		ClientID: "x", RedirectURL: "y", Provider: oauth.Google(),
	})
	req, _ := c.AuthCodeURL()
	if !strings.Contains(req.URL, "openid") {
		t.Error("default scopes must include openid")
	}
}

func TestAuthCodeURL_callerScopesVerbatim(t *testing.T) {
	// Caller-supplied scopes are used as-is (no openid injected) — required for
	// plain-OAuth2 providers like GitHub.
	c, _ := oauth.New(fakeProvider{}, oauth.Config{
		ClientID: "x", RedirectURL: "y", Provider: oauth.GitHub(),
		Scopes: []string{"read:user", "user:email"},
	})
	req, _ := c.AuthCodeURL()
	if strings.Contains(req.URL, "openid") {
		t.Error("openid must not be injected into caller-supplied scopes")
	}
}

func TestMicrosoftPreset(t *testing.T) {
	p := oauth.Microsoft("common")
	if !strings.Contains(p.Issuer, "common") || !strings.Contains(p.AuthURL, "authorize") || p.JWKSURL == "" {
		t.Errorf("unexpected Microsoft preset: %+v", p)
	}
}

func TestExchange_contextDeadline(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(50 * time.Millisecond)
		_, _ = w.Write([]byte(`{"id_token":"x"}`))
	}))
	defer srv.Close()
	c := newClient(t, srv)
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if _, err := c.Exchange(ctx, "c", "v"); err == nil {
		t.Error("expected a context-deadline error")
	}
}
