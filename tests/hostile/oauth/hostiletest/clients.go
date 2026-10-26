package hostiletest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/oauth"
)

// OIDCClient builds a client for the OIDC provider testIssuer whose signing
// keys come from jwksURL.
func OIDCClient(t *testing.T, jwksURL string, mut func(*oauth.Config)) *oauth.Client {
	t.Helper()
	cfg := oauth.Config{
		ClientID:    ClientID,
		RedirectURL: "https://app.example/cb",
		Provider: oauth.Provider{
			Issuer:   Issuer,
			AuthURL:  "https://idp.example/auth",
			TokenURL: "https://idp.example/token",
			JWKSURL:  jwksURL,
		},
	}
	if mut != nil {
		mut(&cfg)
	}
	c, err := oauth.New(SilentProvider{}, cfg)
	if err != nil {
		t.Fatalf("oauth.New: %v", err)
	}
	return c
}

// JWKSClient serves doc as the JWKS and returns a client verifying against it
// together with the server (for hit counts).
func JWKSClient(t *testing.T, doc []byte) (*oauth.Client, *IDP) {
	t.Helper()
	srv := Serve(t, StaticBody(doc))
	return OIDCClient(t, srv.URL, nil), srv
}

// TokenClient builds an OIDC client whose token endpoint is tokenURL.
func TokenClient(t *testing.T, tokenURL string, mut func(*oauth.Config)) *oauth.Client {
	t.Helper()
	return OIDCClient(t, "https://idp.example/jwks", func(c *oauth.Config) {
		c.Provider.TokenURL = tokenURL
		if mut != nil {
			mut(c)
		}
	})
}

// UserinfoClient builds a plain-OAuth2 client reading its profile from url.
func UserinfoClient(t *testing.T, url string, mut func(*oauth.Config)) *oauth.Client {
	t.Helper()
	cfg := oauth.Config{
		ClientID:    ClientID,
		RedirectURL: "https://app.example/cb",
		Scopes:      []string{"read:user"},
		Provider: oauth.Provider{
			AuthURL:     "https://idp.example/auth",
			TokenURL:    "https://idp.example/token",
			UserInfoURL: url,
		},
	}
	if mut != nil {
		mut(&cfg)
	}
	c, err := oauth.New(SilentProvider{}, cfg)
	if err != nil {
		t.Fatalf("oauth.New: %v", err)
	}
	return c
}

// Ctx returns a context that bounds a single attack, so a regression that
// hangs fails the test instead of the run.
func Ctx(t *testing.T) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	t.Cleanup(cancel)
	return c
}

// Verify is the one-line path "a token arrives at the callback".
func Verify(t *testing.T, c *oauth.Client, token string) (*oauth.IDClaims, error) {
	t.Helper()
	return c.VerifyIDToken(Ctx(t), token, Nonce)
}

// MustRejectToken fails unless err is the ErrIDTokenInvalid refusal.
func MustRejectToken(t *testing.T, got *oauth.IDClaims, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("hostile token ACCEPTED as %+v", got)
	}
	if !errors.Is(err, oauth.ErrIDTokenInvalid) {
		t.Fatalf("hostile token failed, but not as ErrIDTokenInvalid: %v", err)
	}
}
