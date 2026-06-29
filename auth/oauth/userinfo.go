package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// userInfoMaxBytes caps a userinfo response so a hostile or broken endpoint
// cannot exhaust memory.
const userInfoMaxBytes = 1 << 20

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
// Returns ErrNoUserInfo if the provider has no UserInfoURL, or ErrUserInfo on a
// transport error, a non-2xx response, or an undecodable body.
func (c *Client) UserInfo(ctx context.Context, accessToken string) (map[string]any, error) {
	if c.cfg.Provider.UserInfoURL == "" {
		return nil, ErrNoUserInfo
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.Provider.UserInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: build request: %w", ErrUserInfo, err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUserInfo, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, userInfoMaxBytes))
	if err != nil {
		return nil, fmt.Errorf("%w: read: %w", ErrUserInfo, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%w: status %d", ErrUserInfo, resp.StatusCode)
	}

	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("%w: decode: %w", ErrUserInfo, err)
	}
	return out, nil
}
