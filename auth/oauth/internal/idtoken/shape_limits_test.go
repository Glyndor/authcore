package idtoken_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth"
	"github.com/Glyndor/authcore/auth/oauth/internal/oauthtest"
)

func verifyJunk(t *testing.T, token string) error {
	t.Helper()
	key := oauthtest.MustRSA(t)
	srv := oauthtest.JWKSServer(t, &key.PublicKey)
	defer srv.Close()
	c := oauthtest.NewClient(t, srv)
	_, err := c.VerifyIDToken(context.Background(), token, "n")
	if !errors.Is(err, oauth.ErrIDTokenInvalid) {
		t.Fatalf("expected ErrIDTokenInvalid, got %v", err)
	}
	return err
}

func TestIDTokenLengthCapIsExact(t *testing.T) {
	const cap = 16 * 1024
	if err := verifyJunk(t, strings.Repeat("a", cap)); strings.Contains(err.Error(), "too large") {
		t.Fatalf("a token of exactly %d bytes is within the cap: %v", cap, err)
	}
	if err := verifyJunk(t, strings.Repeat("a", cap+1)); !strings.Contains(err.Error(), "too large") {
		t.Fatalf("a token one byte over the cap must be refused as too large: %v", err)
	}
}

func TestIDTokenAlphabetCheckStartsAtTheFirstByte(t *testing.T) {
	err := verifyJunk(t, "\naaaa.bbbb.cccc")
	if !strings.Contains(err.Error(), "byte 0 is outside the base64url alphabet") {
		t.Fatalf("a leading stray byte must be named by the alphabet check: %v", err)
	}
}
