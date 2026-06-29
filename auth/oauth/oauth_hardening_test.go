package oauth_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth"
)

// ---- HTTPS enforcement ------------------------------------------------------

func TestNew_rejectsNonHTTPSEndpoint(t *testing.T) {
	_, err := oauth.New(fakeProvider{}, oauth.Config{
		ClientID:    "x",
		RedirectURL: "https://app.example/cb",
		Provider: oauth.Provider{
			Issuer:   "https://id.example",
			AuthURL:  "http://id.example/auth", // plaintext — must be rejected
			TokenURL: "https://id.example/token",
			JWKSURL:  "https://id.example/jwks",
		},
	})
	if err == nil {
		t.Error("expected a non-https endpoint to be rejected")
	}
}

func TestNew_allowsLoopbackHTTP(t *testing.T) {
	_, err := oauth.New(fakeProvider{}, oauth.Config{
		ClientID:    "x",
		RedirectURL: "http://localhost:8080/cb",
		Provider: oauth.Provider{
			AuthURL:     "http://127.0.0.1:9000/auth",
			TokenURL:    "http://127.0.0.1:9000/token",
			UserInfoURL: "http://127.0.0.1:9000/userinfo",
		},
	})
	if err != nil {
		t.Errorf("loopback http should be allowed for local dev, got %v", err)
	}
}

func TestDiscover_rejectsNonHTTPSIssuer(t *testing.T) {
	if _, err := oauth.Discover(context.Background(), "http://id.example", nil); err == nil {
		t.Error("expected a non-https issuer to be rejected before any fetch")
	}
}

// ---- OAuth2 Exchange no longer requires an id_token -------------------------

func TestExchange_oauth2ReturnsTokensWithoutIDToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// A plain-OAuth2 provider returns no id_token.
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":"bearer"}`))
	}))
	defer srv.Close()

	c, err := oauth.New(fakeProvider{}, oauth.Config{
		ClientID:    testClientID,
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

// ---- JWKS: encryption keys are not used for signature verification ----------

func TestVerifyIDToken_encUseKeySkipped(t *testing.T) {
	key := mustRSA(t)
	n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())
	// The only key carries use:"enc" — it must not be selected to verify a signature.
	doc := fmt.Sprintf(`{"keys":[{"kty":"RSA","kid":%q,"use":"enc","n":%q,"e":%q}]}`, testKID, n, e)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(doc))
	}))
	defer srv.Close()
	c := newClient(t, srv)

	tok := signIDToken(t, key, testKID, validClaims(srv.URL, "n"))
	if _, err := c.VerifyIDToken(context.Background(), tok, "n"); err == nil {
		t.Error("an enc-use key must not verify a token signature")
	}
}
