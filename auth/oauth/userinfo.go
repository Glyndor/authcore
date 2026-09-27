package oauth

import (
	"bytes"
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
// Returns ErrNoUserInfo if the provider has no UserInfoURL, or ErrUserInfo on
// an empty bearer token, a transport error, a non-2xx response, a literal
// "null" body, or any other undecodable body. Numeric values arrive as
// json.Number (via json.Decoder.UseNumber) so large identifiers (e.g. GitHub
// "id") survive the round trip without lossy float64 conversion.
func (c *Client) UserInfo(ctx context.Context, accessToken string) (map[string]any, error) {
	if c.cfg.Provider.UserInfoURL == "" {
		return nil, ErrNoUserInfo
	}
	// An empty bearer would be sent as "Bearer ", and the endpoint may still
	// return 200 with an anonymous profile, so refuse it before the round trip.
	if accessToken == "" {
		return nil, fmt.Errorf("%w: access token must not be empty", ErrUserInfo)
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

	// Decode with UseNumber so a 53-bit-plus integer id (e.g. 9007199254740993)
	// does not collapse onto its neighbour via float64. A trailing-junk check
	// follows the object so a body like {"id":1}garbage is refused, matching
	// json.Unmarshal's strict behaviour.
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var raw json.RawMessage
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("%w: decode: %w", ErrUserInfo, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("%w: trailing data after JSON value", ErrUserInfo)
	}
	// A literal "null" is not a user object. Refuse it instead of returning an
	// empty map (the caller would otherwise treat the absence of data as
	// success).
	if string(raw) == "null" {
		return nil, fmt.Errorf("%w: response was null", ErrUserInfo)
	}
	// Re-decode the raw value with UseNumber preserved (json.Unmarshal ignores
	// the decoder's option) so numeric claims arrive as json.Number.
	dec2 := json.NewDecoder(bytes.NewReader(raw))
	dec2.UseNumber()
	var out map[string]any
	if err := dec2.Decode(&out); err != nil {
		return nil, fmt.Errorf("%w: decode: %w", ErrUserInfo, err)
	}
	// A 200 carrying an OAuth error object, or an empty object, is not a
	// profile: both returned a nil error before 2026-09-25, and a caller
	// keying accounts on info["id"] got nil for every such login. Exchange
	// already refuses the error object the same way.
	if _, isError := out["error"]; isError {
		return nil, fmt.Errorf("%w: provider returned an error object", ErrUserInfo)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: provider returned an empty profile", ErrUserInfo)
	}
	return out, nil
}
