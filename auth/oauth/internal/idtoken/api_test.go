package idtoken_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth"
	"github.com/Glyndor/authcore/auth/oauth/internal/oauthtest"
)

func TestVerifyIDToken_rejectsExtraAudience(t *testing.T) {
	key := oauthtest.MustRSA(t)
	srv := oauthtest.JWKSServer(t, &key.PublicKey)
	defer srv.Close()
	c := oauthtest.NewClient(t, srv)

	cl := oauthtest.ValidClaims(srv.URL, "n")
	cl["aud"] = []string{oauthtest.ClientID, "other"}
	cl["azp"] = oauthtest.ClientID
	tok := oauthtest.SignIDToken(t, key, oauthtest.KID, cl)
	if _, err := c.VerifyIDToken(context.Background(), tok, "n"); !errors.Is(err, oauth.ErrIDTokenInvalid) {
		t.Fatalf("expected ErrIDTokenInvalid, got %v", err)
	}
	// Acceptance pair: a token whose only audience is the client id verifies.
	cl["aud"] = []string{oauthtest.ClientID}
	delete(cl, "azp")
	tok = oauthtest.SignIDToken(t, key, oauthtest.KID, cl)
	if _, err := c.VerifyIDToken(context.Background(), tok, "n"); err != nil {
		t.Fatalf("acceptance: VerifyIDToken, got %v", err)
	}
}

func TestVerifyIDToken_requiresIssuedAt(t *testing.T) {
	key := oauthtest.MustRSA(t)
	srv := oauthtest.JWKSServer(t, &key.PublicKey)
	defer srv.Close()
	c := oauthtest.NewClient(t, srv)

	// validClaims already sets iat; remove it for the rejection case.
	cl := oauthtest.ValidClaims(srv.URL, "n")
	delete(cl, "iat")
	tok := oauthtest.SignIDToken(t, key, oauthtest.KID, cl)
	if _, err := c.VerifyIDToken(context.Background(), tok, "n"); !errors.Is(err, oauth.ErrIDTokenInvalid) {
		t.Fatalf("expected ErrIDTokenInvalid on missing iat, got %v", err)
	}
	// Acceptance pair: the same token with iat set verifies.
	cl["iat"] = oauthtest.ValidClaims(srv.URL, "n")["iat"]
	tok = oauthtest.SignIDToken(t, key, oauthtest.KID, cl)
	if _, err := c.VerifyIDToken(context.Background(), tok, "n"); err != nil {
		t.Fatalf("acceptance: VerifyIDToken with iat, got %v", err)
	}
}

// An iat carried as a quoted string is a non-numeric NumericDate; RFC 7519
// requires a JSON number. The token must fail verification on that basis.
func TestVerifyIDToken_iatStringRejected(t *testing.T) {
	key := oauthtest.MustRSA(t)
	srv := oauthtest.JWKSServer(t, &key.PublicKey)
	defer srv.Close()
	c := oauthtest.NewClient(t, srv)

	cl := oauthtest.ValidClaims(srv.URL, "n")
	cl["iat"] = "1700000000" // quoted: not a JSON number
	tok := oauthtest.SignIDToken(t, key, oauthtest.KID, cl)

	_, err := c.VerifyIDToken(context.Background(), tok, "n")
	if !errors.Is(err, oauth.ErrIDTokenInvalid) {
		t.Fatalf("expected ErrIDTokenInvalid, got %v", err)
	}
	if !strings.Contains(err.Error(), "iat") {
		t.Fatalf("error does not name the rejected claim (want iat), got %v", err)
	}
}

// An aud carried as a JSON number has no string form to match the configured
// client id. A multi-tenant validator doesn't help: the only audience the
// caller ever trusts is the one it named as ClientID.
func TestVerifyIDToken_audNumberRejected(t *testing.T) {
	key := oauthtest.MustRSA(t)
	srv := oauthtest.JWKSServer(t, &key.PublicKey)
	defer srv.Close()
	c := oauthtest.NewClient(t, srv)

	cl := oauthtest.ValidClaims(srv.URL, "n")
	cl["aud"] = 12345 // JSON number, not a string
	tok := oauthtest.SignIDToken(t, key, oauthtest.KID, cl)

	_, err := c.VerifyIDToken(context.Background(), tok, "n")
	if !errors.Is(err, oauth.ErrIDTokenInvalid) {
		t.Fatalf("expected ErrIDTokenInvalid, got %v", err)
	}
	if !strings.Contains(err.Error(), "aud") {
		t.Fatalf("error does not name the rejected claim (want aud), got %v", err)
	}
}

func TestVerifyIDToken_oversizedRejected(t *testing.T) {
	key := oauthtest.MustRSA(t)
	srv := oauthtest.JWKSServer(t, &key.PublicKey)
	defer srv.Close()
	c := oauthtest.NewClient(t, srv)
	// A well-formed but oversized token: signed correctly against the key the
	// JWKS advertises, with a large custom claim that pushes the encoded form
	// past the size guard. A run of raw bytes would be refused by the JWT
	// parser before the size guard, and the test would pass for the wrong
	// reason.
	cl := oauthtest.ValidClaims(srv.URL, "n")
	cl["junk"] = strings.Repeat("a", 20000)
	tok := oauthtest.SignIDToken(t, key, oauthtest.KID, cl)
	if _, err := c.VerifyIDToken(context.Background(), tok, "n"); err == nil {
		t.Error("an oversized id token must be rejected before parsing")
	} else if !strings.Contains(err.Error(), "too large") {
		t.Fatalf("refusal must name the size guard, got %v", err)
	}
}

// ---- HTTPS enforcement ------------------------------------------------------

// ---- OAuth2 Exchange no longer requires an id_token -------------------------

// ---- JWKS: encryption keys are not used for signature verification ----------

// An ID token with no "sub" identifies nobody. Accepting one hands the consumer
// an empty subject, which their storage layer is liable to treat as a real
// account key. The guard that rejects it survived being deleted with the suite
// green — every other test signs a token that has a subject.
func TestVerifyIDToken_rejectsATokenWithNoSubject(t *testing.T) {
	key := oauthtest.MustRSA(t)
	srv := oauthtest.JWKSServer(t, &key.PublicKey)
	c := oauthtest.NewClient(t, srv)

	claims := oauthtest.ValidClaims(srv.URL, "n")
	delete(claims, "sub")
	tok := oauthtest.SignIDToken(t, key, oauthtest.KID, claims)

	_, err := c.VerifyIDToken(context.Background(), tok, "n")
	if err == nil {
		t.Fatal("an ID token without a subject must be refused")
	}
	if !strings.Contains(err.Error(), "subject") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
}

// Paths that accepted more than they should until 2026-09-25: a UserInfo 200
// that is not a profile, Basic credentials sent without the RFC 6749 form
// encoding, a caller's AuthMethods slice kept after New, and a second
// spelling of one ID token.

// flipUnusedBit returns s with its last base64url character changed so that
// it decodes to the same bytes under the lenient decoder.
func flipUnusedBit(t *testing.T, s string) string {
	t.Helper()
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	i := strings.IndexByte(alphabet, s[len(s)-1])
	return s[:len(s)-1] + string(alphabet[i^1])
}

func TestVerifyIDToken_refusesASecondSpellingOfTheToken(t *testing.T) {
	key := oauthtest.MustRSA(t)
	srv := oauthtest.JWKSServer(t, &key.PublicKey)
	defer srv.Close()
	c := oauthtest.NewClient(t, srv)
	tok := oauthtest.SignIDToken(t, key, oauthtest.KID, oauthtest.ValidClaims(srv.URL, "n"))

	if _, err := c.VerifyIDToken(context.Background(), tok, "n"); err != nil {
		t.Fatalf("the token as signed: %v, want accepted", err)
	}
	for name, tc := range map[string]struct{ token, fragment string }{
		"line feed in the signature": {tok[:len(tok)-10] + "\n" + tok[len(tok)-10:], "outside the base64url alphabet"},
		"unused bits set":            {flipUnusedBit(t, tok), "illegal base64 data"},
	} {
		_, err := c.VerifyIDToken(context.Background(), tc.token, "n")
		if !errors.Is(err, oauth.ErrIDTokenInvalid) || !strings.Contains(err.Error(), tc.fragment) {
			t.Errorf("%s: %v, want ErrIDTokenInvalid naming %q", name, err, tc.fragment)
		}
	}
}

// ---- OAuth2 (userinfo) path -------------------------------------------------

// ---- EC (ES256) end-to-end --------------------------------------------------

// ---- claim variants ---------------------------------------------------------

func TestVerifyIDToken_audArrayAndStringEmailVerified(t *testing.T) {
	key := oauthtest.MustRSA(t)
	srv := oauthtest.JWKSServer(t, &key.PublicKey)
	defer srv.Close()
	c := oauthtest.NewClient(t, srv)

	// Multi-aud tokens (aud names this client plus another) are refused even
	// when azp matches: the verifier accepts only the configured client id as
	// the sole audience.
	t.Run("multi-aud rejected", func(t *testing.T) {
		cl := oauthtest.ValidClaims(srv.URL, "n")
		cl["aud"] = []string{oauthtest.ClientID, "another"}
		cl["azp"] = oauthtest.ClientID
		cl["email_verified"] = "true"
		tok := oauthtest.SignIDToken(t, key, oauthtest.KID, cl)
		if _, err := c.VerifyIDToken(context.Background(), tok, "n"); err == nil {
			t.Error("expected rejection of a multi-audience token")
		}
	})
	// The string form of email_verified still parses when the audience is the
	// single configured client id.
	t.Run("string email_verified parses", func(t *testing.T) {
		cl := oauthtest.ValidClaims(srv.URL, "n")
		cl["email_verified"] = "true"
		tok := oauthtest.SignIDToken(t, key, oauthtest.KID, cl)
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
	key := oauthtest.MustRSA(t)
	srv := oauthtest.JWKSServer(t, &key.PublicKey)
	defer srv.Close()
	c := oauthtest.NewClient(t, srv)

	// Our client id is in aud, but the token was authorized for another client.
	cl := oauthtest.ValidClaims(srv.URL, "n")
	cl["aud"] = []string{oauthtest.ClientID, "another"}
	cl["azp"] = "another"
	tok := oauthtest.SignIDToken(t, key, oauthtest.KID, cl)

	if _, err := c.VerifyIDToken(context.Background(), tok, "n"); err == nil {
		t.Error("expected rejection of a multi-audience token whose azp is another client")
	}
}

// ---- JWKS error paths -------------------------------------------------------

// ---- config / presets -------------------------------------------------------
