package oauth

import (
	"context"

	"github.com/Glyndor/authcore/auth/oauth/internal/userinfo"
)

// UserInfo fetches the authenticated user's profile from a plain-OAuth2
// provider's userinfo endpoint, presenting the access token as a Bearer
// credential. Use it for providers that do not issue an ID token (GitHub,
// Discord, …); for OIDC providers prefer VerifyIDToken.
//
// The returned map is the provider's raw JSON — its shape is provider-specific,
// so read the fields you need (e.g. GitHub "id"/"login", Discord "id"/
// "username"). The provider's stable user id is the value to key your account
// on, never the email or display name.
//
// Returns ErrNoUserInfo if the provider has no UserInfoURL, or ErrUserInfo on
// an empty bearer token, a transport error, a non-2xx response, a literal
// "null" body, or any other undecodable body. Numeric values arrive as
// json.Number (via json.Decoder.UseNumber) so large identifiers (e.g. GitHub
// "id") survive the round trip without lossy float64 conversion.
func (c *Client) UserInfo(ctx context.Context, accessToken string) (map[string]any, error) {
	if !c.built() {
		return nil, errNotBuilt
	}
	if c.cfg.Provider.UserInfoURL == "" {
		return nil, ErrNoUserInfo
	}
	return userinfo.Fetch(ctx, c.http, c.cfg.Provider.UserInfoURL, accessToken, ErrUserInfo)
}
