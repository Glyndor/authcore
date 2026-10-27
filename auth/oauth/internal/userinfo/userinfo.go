// Package userinfo fetches the profile of a plain-OAuth2 user from the provider's userinfo endpoint.
package userinfo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// userInfoMaxBytes caps a userinfo response so a hostile or broken endpoint
// cannot exhaust memory.
const userInfoMaxBytes = 1 << 20

// Fetch requests the profile at endpoint with accessToken as a Bearer
// credential. Every failure wraps errUserInfo (the public ErrUserInfo
// sentinel). See oauth.Client.UserInfo for the contract.
func Fetch(ctx context.Context, h *http.Client, endpoint, accessToken string, errUserInfo error) (map[string]any, error) {
	// An empty bearer would be sent as "Bearer ", and the endpoint may still
	// return 200 with an anonymous profile, so refuse it before the round trip.
	if accessToken == "" {
		return nil, fmt.Errorf("%w: access token must not be empty", errUserInfo)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: build request: %w", errUserInfo, err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := h.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errUserInfo, err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Read one byte past the cap: a body that does not fit is refused whole,
	// never read as the prefix that does fit.
	body, err := io.ReadAll(io.LimitReader(resp.Body, userInfoMaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: read: %w", errUserInfo, err)
	}
	if len(body) > userInfoMaxBytes {
		return nil, fmt.Errorf("%w: response larger than %d bytes", errUserInfo, userInfoMaxBytes)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%w: status %d", errUserInfo, resp.StatusCode)
	}

	// Walk the body's shape first, so one made of the shortest possible values
	// is refused before the decoder allocates a value for each of them.
	if err := checkShape(body); err != nil {
		return nil, fmt.Errorf("%w: %w", errUserInfo, err)
	}
	// Decode once, with UseNumber so a 53-bit-plus integer id (e.g.
	// 9007199254740993) does not collapse onto its neighbour via float64. A
	// trailing-junk check follows the object so a body like {"id":1}garbage is
	// refused, matching json.Unmarshal's strict behaviour.
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var out map[string]any
	if err := dec.Decode(&out); err != nil {
		return nil, fmt.Errorf("%w: decode: %w", errUserInfo, err)
	}
	// More reports false before a closing bracket, so it would let {"id":1}}
	// through; the next token must be the end of the input.
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: trailing data after JSON value", errUserInfo)
	}
	// A literal "null" is not a user object. Refuse it instead of returning an
	// empty map (the caller would otherwise treat the absence of data as
	// success).
	if out == nil {
		return nil, fmt.Errorf("%w: response was null", errUserInfo)
	}
	// A 200 carrying an OAuth error object, or an empty object, is not a
	// profile: both returned a nil error before 2026-09-25, and a caller
	// keying accounts on info["id"] got nil for every such login. Exchange
	// already refuses the error object the same way.
	if _, isError := out["error"]; isError {
		return nil, fmt.Errorf("%w: provider returned an error object", errUserInfo)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: provider returned an empty profile", errUserInfo)
	}
	return out, nil
}
