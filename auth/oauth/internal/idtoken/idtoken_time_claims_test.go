package idtoken_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/oauth"
	"github.com/Glyndor/authcore/auth/oauth/internal/oauthtest"
)

// VerifyIDToken must treat exp as required and iat as not-in-the-future.
// golang-jwt's WithExpirationRequired refuses a token without exp; its
// WithIssuedAt refuses a token issued in the future (no leeway by default).
// Each rejection is pinned on the message fragment golang-jwt produces, so
// a parser swap that changes the wording is visible here.
func TestVerifyIDToken_timeClaimsEnforced(t *testing.T) {
	key := oauthtest.MustRSA(t)
	srv := oauthtest.JWKSServer(t, &key.PublicKey)
	defer srv.Close()
	c := oauthtest.NewClient(t, srv)
	ctx := context.Background()

	t.Run("missing exp", func(t *testing.T) {
		cl := oauthtest.ValidClaims(srv.URL, "n")
		delete(cl, "exp")
		tok := oauthtest.SignIDToken(t, key, oauthtest.KID, cl)
		_, err := c.VerifyIDToken(ctx, tok, "n")
		if !errors.Is(err, oauth.ErrIDTokenInvalid) {
			t.Fatalf("expected ErrIDTokenInvalid, got %v", err)
		}
		if !strings.Contains(err.Error(), "exp claim is required") {
			t.Fatalf("refusal must name the missing exp, got %v", err)
		}
	})

	t.Run("iat in the future", func(t *testing.T) {
		cl := oauthtest.ValidClaims(srv.URL, "n")
		cl["iat"] = time.Now().Add(time.Hour).Unix()
		tok := oauthtest.SignIDToken(t, key, oauthtest.KID, cl)
		_, err := c.VerifyIDToken(ctx, tok, "n")
		if !errors.Is(err, oauth.ErrIDTokenInvalid) {
			t.Fatalf("expected ErrIDTokenInvalid, got %v", err)
		}
		if !strings.Contains(err.Error(), "token used before issued") {
			t.Fatalf("refusal must name the future iat, got %v", err)
		}
	})

	t.Run("validClaims verifies", func(t *testing.T) {
		tok := oauthtest.SignIDToken(t, key, oauthtest.KID, oauthtest.ValidClaims(srv.URL, "n"))
		if _, err := c.VerifyIDToken(ctx, tok, "n"); err != nil {
			t.Fatalf("acceptance: VerifyIDToken with validClaims, got %v", err)
		}
	})
}
