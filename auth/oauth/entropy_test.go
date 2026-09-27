package oauth_test

import (
	"encoding/base64"
	"net/url"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth"
)

// State, nonce and verifier must each carry 32 random bytes. The encoding is
// base64url without padding, so the on-the-wire length is fixed:
// ceil(32 * 4 / 3) = 43. A regression that drops the byte count, or swaps the
// encoding to one that pads/expands, would still mint a "secret" every caller
// would trust. Pin the bytes and the length by name so a regression is visible
// at the offending field.
func TestAuthCodeURL_tokensCarry32RandomBytes(t *testing.T) {
	c, err := oauth.New(fakeProvider{}, oauth.Config{
		ClientID: testClientID, RedirectURL: "https://app.example/cb", Provider: oauth.Google(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req, err := c.AuthCodeURL()
	if err != nil {
		t.Fatalf("AuthCodeURL: %v", err)
	}

	for field, value := range map[string]string{
		"State":    req.State,
		"Nonce":    req.Nonce,
		"Verifier": req.Verifier,
	} {
		raw, err := base64.RawURLEncoding.DecodeString(value)
		if err != nil {
			t.Errorf("%s: base64url decode failed: %v", field, err)
			continue
		}
		if len(raw) != 32 {
			t.Errorf("%s: decoded length = %d, want 32", field, len(raw))
		}
		if len(value) != 43 {
			t.Errorf("%s: encoded length = %d, want 43", field, len(value))
		}
	}

	u, err := url.Parse(req.URL)
	if err != nil {
		t.Fatalf("parse Authorization URL: %v", err)
	}
	q := u.Query()
	if q.Get("state") != req.State || q.Get("nonce") != req.Nonce {
		t.Errorf("Authorization URL state/nonce do not match the returned secrets: state=%q nonce=%q",
			q.Get("state"), q.Get("nonce"))
	}
}
