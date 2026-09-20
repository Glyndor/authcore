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
	"net/url"
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
		// Return a valid JSON object so the rejection must come from the
		// status check, not from decoding an empty body.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"forbidden"}`))
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
	_, err := oauth.New(fakeProvider{}, oauth.Config{
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

	// Multi-aud tokens (aud names this client plus another) are refused even
	// when azp matches: the verifier accepts only the configured client id as
	// the sole audience.
	t.Run("multi-aud rejected", func(t *testing.T) {
		cl := validClaims(srv.URL, "n")
		cl["aud"] = []string{testClientID, "another"}
		cl["azp"] = testClientID
		cl["email_verified"] = "true"
		tok := signIDToken(t, key, testKID, cl)
		if _, err := c.VerifyIDToken(context.Background(), tok, "n"); err == nil {
			t.Error("expected rejection of a multi-audience token")
		}
	})
	// The string form of email_verified still parses when the audience is the
	// single configured client id.
	t.Run("string email_verified parses", func(t *testing.T) {
		cl := validClaims(srv.URL, "n")
		cl["email_verified"] = "true"
		tok := signIDToken(t, key, testKID, cl)
		claims, err := c.VerifyIDToken(context.Background(), tok, "n")
		if err != nil {
			t.Fatalf("VerifyIDToken: %v", err)
		}
		if !claims.EmailVerified {
			t.Error("string email_verified \"true\" not parsed as true")
		}
	})
}

func TestVerifyIDToken_multiAudWrongAZPRejected(t *testing.T) {
	key := mustRSA(t)
	srv := jwksServer(t, &key.PublicKey)
	defer srv.Close()
	c := newClient(t, srv)

	// Our client id is in aud, but the token was authorized for another client.
	cl := validClaims(srv.URL, "n")
	cl["aud"] = []string{testClientID, "another"}
	cl["azp"] = "another"
	tok := signIDToken(t, key, testKID, cl)

	if _, err := c.VerifyIDToken(context.Background(), tok, "n"); err == nil {
		t.Error("expected rejection of a multi-audience token whose azp is another client")
	}
}

// ---- JWKS error paths -------------------------------------------------------

func TestVerifyIDToken_jwksNon200(t *testing.T) {
	key := mustRSA(t)
	// Return valid JWKS JSON at the failing status so the rejection must come
	// from the status check, not from decoding an empty body.
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"keys":[]}`))
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
	// No scopes set -> the OIDC default set is used. The test pins the exact
	// decoded value so a regression that drops a scope or reorders them
	// (e.g. building a different "openid email profile" sequence) does not
	// pass on the "contains openid" check alone.
	c, _ := oauth.New(fakeProvider{}, oauth.Config{
		ClientID: "x", RedirectURL: "https://app.example/cb", Provider: oauth.Google(),
	})
	req, _ := c.AuthCodeURL()
	u, _ := url.Parse(req.URL)
	if got, want := u.Query().Get("scope"), "openid email profile"; got != want {
		t.Errorf("scope = %q, want %q", got, want)
	}
}

func TestAuthCodeURL_callerScopesVerbatim(t *testing.T) {
	// Caller-supplied scopes are used as-is (no openid injected) — required for
	// plain-OAuth2 providers like GitHub.
	c, _ := oauth.New(fakeProvider{}, oauth.Config{
		ClientID: "x", RedirectURL: "https://app.example/cb", Provider: oauth.GitHub(),
		Scopes: []string{"read:user", "user:email"},
	})
	req, _ := c.AuthCodeURL()
	if strings.Contains(req.URL, "openid") {
		t.Error("openid must not be injected into caller-supplied scopes")
	}
}

func TestMicrosoftPreset(t *testing.T) {
	const tenant = "9188040d-6c67-4c5b-b112-36a304b66dad"
	p, err := oauth.Microsoft(tenant)
	if err != nil {
		t.Fatalf("Microsoft(%q): %v", tenant, err)
	}
	if !strings.Contains(p.Issuer, tenant) || !strings.Contains(p.AuthURL, "authorize") || p.JWKSURL == "" {
		t.Errorf("unexpected Microsoft preset: %+v", p)
	}
	// A non-GUID tenant (the previously accepted verified-domain form) is
	// refused with a message that names the requirement.
	if _, err := oauth.Microsoft("contoso.onmicrosoft.com"); err == nil {
		t.Error("Microsoft must refuse a non-GUID tenant id")
	} else if !strings.Contains(err.Error(), "GUID") {
		t.Errorf("refusal must name the GUID requirement, got %v", err)
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
