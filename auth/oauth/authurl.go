package oauth

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/Glyndor/authcore/auth/oauth/internal/pkce"
)

// AuthRequest is the result of AuthCodeURL. Redirect the user to URL, and
// persist State, Nonce and Verifier somewhere only this browser can return them
// (a short-lived signed/HttpOnly cookie or the server session) — all three are
// needed to validate the callback.
type AuthRequest struct {
	// URL is the provider authorization URL to redirect the user to.
	URL string
	// State must be compared against the "state" query parameter on callback;
	// a mismatch means CSRF or a stale request — reject it.
	State string
	// Nonce must be handed to VerifyIDToken; it binds the ID token to this request.
	Nonce string
	// Verifier is the PKCE code_verifier; pass it to Exchange.
	Verifier string
}

// AuthCodeURL generates fresh state, nonce and a PKCE verifier, and builds the
// authorization redirect URL. Every call is independent.
func (c *Client) AuthCodeURL() (*AuthRequest, error) {
	if !c.built() {
		return nil, errNotBuilt
	}
	state, err := pkce.RandomURLToken()
	if err != nil {
		return nil, err
	}
	nonce, err := pkce.RandomURLToken()
	if err != nil {
		return nil, err
	}
	verifier, err := pkce.RandomURLToken()
	if err != nil {
		return nil, err
	}

	// Parse the configured AuthURL and merge our parameters onto its existing
	// query string with Set, so a config that already carries state or
	// code_challenge does not produce duplicates. Most OIDC servers read the
	// first value of a repeated key, which was the caller's pre-existing one
	// and not the one we just generated.
	u, err := url.Parse(c.cfg.Provider.AuthURL)
	if err != nil {
		return nil, fmt.Errorf("oauth: provider auth URL is not parseable: %w", err)
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", c.cfg.ClientID)
	q.Set("redirect_uri", c.cfg.RedirectURL)
	q.Set("scope", strings.Join(c.cfg.Scopes, " "))
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", pkce.Challenge(verifier))
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()
	return &AuthRequest{
		URL:      u.String(),
		State:    state,
		Nonce:    nonce,
		Verifier: verifier,
	}, nil
}
