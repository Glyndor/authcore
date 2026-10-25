package idtoken_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth"
	"github.com/Glyndor/authcore/auth/oauth/internal/oauthtest"
)

// A permissive issuer predicate (one that returns true for every input)
// must still refuse an empty iss. internal/idtoken/idtoken.go short-circuits the predicate
// for an empty string before consulting it, with a message that names the
// rejected issuer. The acceptance pair confirms the same predicate and the
// same kid/alg setup verifying a non-empty iss, so the rejection here is
// the iss-empty branch and not, say, a JWKS error.
func TestVerifyIDToken_issuerPredicateRejectsEmptyIss(t *testing.T) {
	key := oauthtest.MustRSA(t)
	srv := oauthtest.JWKSServer(t, &key.PublicKey)
	defer srv.Close()

	c, err := oauth.New(oauthtest.FakeProvider{}, oauth.Config{
		ClientID:    oauthtest.ClientID,
		RedirectURL: "https://app.example.com/cb",
		Provider: oauth.Provider{
			AuthURL: srv.URL + "/auth", TokenURL: srv.URL + "/t", JWKSURL: srv.URL,
		},
		IssuerValidator: func(string) bool { return true },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()

	t.Run("empty iss is refused", func(t *testing.T) {
		cl := oauthtest.ValidClaims(srv.URL, "n")
		cl["iss"] = ""
		tok := oauthtest.SignIDToken(t, key, oauthtest.KID, cl)
		_, err := c.VerifyIDToken(ctx, tok, "n")
		if !errors.Is(err, oauth.ErrIDTokenInvalid) {
			t.Fatalf("expected ErrIDTokenInvalid, got %v", err)
		}
		if !strings.Contains(err.Error(), `issuer "" rejected`) {
			t.Fatalf("refusal must name the empty issuer, got %v", err)
		}
	})

	t.Run("non-empty iss verifies", func(t *testing.T) {
		tok := oauthtest.SignIDToken(t, key, oauthtest.KID, oauthtest.ValidClaims("https://any.example", "n"))
		if _, err := c.VerifyIDToken(ctx, tok, "n"); err != nil {
			t.Fatalf("acceptance: predicate approved issuer, got %v", err)
		}
	})
}
