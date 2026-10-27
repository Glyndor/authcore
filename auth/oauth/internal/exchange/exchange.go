// Package exchange performs the authorization-code exchange at the token endpoint and decodes the
// token response.
package exchange

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/Glyndor/authcore/auth/oauth/internal/clientauth"
	"github.com/Glyndor/authcore/auth/oauth/internal/safetext"
)

// Tokens is the token-endpoint response.
type Tokens struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	ExpiresIn    int    `json:"expires_in"`
}

// exchangeErrorMaxLen caps the description we surface from a provider error
// response. Real error_description values are a short sentence; anything beyond
// a few hundred bytes is the provider echoing form fields or log noise.
const exchangeErrorMaxLen = 512

// responseMaxBytes caps the token response so a hostile or broken endpoint
// cannot exhaust memory.
const responseMaxBytes = 1 << 20

// exchangeCodeMaxLen caps the "error" code of the same response; the codes
// RFC 6749 defines are a few words long.
const exchangeCodeMaxLen = 128

// authCodeMaxLen caps the authorization code Do forwards. Real providers issue
// codes of a few hundred bytes at most; the bound only keeps an unbounded
// callback parameter from being copied to the token endpoint.
const authCodeMaxLen = 8 << 10

// expiresInMax caps the lifetime Do reports: ten years in seconds. No real
// token lives that long, and the cap keeps a caller's seconds-to-Duration
// conversion from overflowing.
const expiresInMax = 10 * 365 * 24 * 3600

// Errors carries the sentinel errors Do wraps its failures with. They are
// owned by the public oauth package (ErrExchange and ErrNoIDToken).
type Errors struct {
	// Exchange wraps every failure of the code exchange.
	Exchange error
	// NoIDToken is returned as is when an OIDC response carries no id_token.
	NoIDToken error
}

// Params is what Do needs from the client configuration.
type Params struct {
	TokenURL    string
	ClientID    string
	RedirectURL string
	// Secret is the static client secret; SecretFunc, when set, replaces it.
	Secret     string
	SecretFunc func(ctx context.Context) (string, error)
	// AuthMethods is what the provider advertises for its token endpoint.
	AuthMethods []string
	// RequireIDToken is true for an OIDC provider.
	RequireIDToken bool
	Errs           Errors
}

// Do swaps an authorization code for tokens at the token endpoint, sending
// the PKCE code_verifier. See oauth.Client.Exchange for the contract.
func Do(ctx context.Context, h *http.Client, p Params, code, verifier string) (*Tokens, error) {
	// Reject empty inputs before talking to the provider. An empty code or
	// verifier would round-trip useless bytes and could mask a wiring bug in
	// the caller (forgot to read the cookie, swapped two variables).
	if code == "" {
		return nil, fmt.Errorf("%w: code must not be empty", p.Errs.Exchange)
	}
	if len(code) > authCodeMaxLen {
		return nil, fmt.Errorf("%w: code is longer than %d bytes", p.Errs.Exchange, authCodeMaxLen)
	}
	if verifier == "" {
		return nil, fmt.Errorf("%w: code_verifier must not be empty", p.Errs.Exchange)
	}

	// Resolve the secret once per Exchange. ClientSecretFunc is invoked here,
	// before any HTTP request is constructed, so a failure (including an empty
	// return) leaves the token endpoint never called. The wrapped sentinel
	// lets callers errors.Is against p.Errs.Exchange.
	secret, err := resolveSecret(ctx, p)
	if err != nil {
		return nil, err
	}

	req, err := newRequest(ctx, p, secret, code, verifier)
	if err != nil {
		return nil, err
	}

	resp, err := h.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", p.Errs.Exchange, err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Cap the response so a hostile or broken endpoint cannot exhaust memory.
	// Read one byte past the cap: a body that does not fit is refused whole,
	// never read as the prefix that does fit.
	body, err := io.ReadAll(io.LimitReader(resp.Body, responseMaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: read response: %w", p.Errs.Exchange, err)
	}
	if len(body) > responseMaxBytes {
		return nil, fmt.Errorf("%w: response larger than %d bytes", p.Errs.Exchange, responseMaxBytes)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%w: status %d", p.Errs.Exchange, resp.StatusCode)
	}

	return decode(p, body, secret, code, verifier)
}

// resolveSecret returns the client secret for this exchange. The secret
// function is invoked here, before any HTTP request is constructed, so a
// failure (including an empty return) leaves the token endpoint never called.
func resolveSecret(ctx context.Context, p Params) (string, error) {
	secret := p.Secret
	if p.SecretFunc != nil {
		s, err := p.SecretFunc(ctx)
		if err != nil {
			return "", fmt.Errorf("%w: client secret function failed: %w", p.Errs.Exchange, err)
		}
		if s == "" {
			return "", fmt.Errorf("%w: client secret function returned an empty secret", p.Errs.Exchange)
		}
		secret = s
	}

	return secret, nil
}

// newRequest builds the token request, authenticating the client with the
// method the provider advertises.
func newRequest(ctx context.Context, p Params, secret, code, verifier string) (*http.Request, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", p.RedirectURL)
	form.Set("client_id", p.ClientID)
	form.Set("code_verifier", verifier)

	method := clientauth.Choose(p.AuthMethods, secret != "")
	if method == clientauth.None && secret != "" {
		return nil, fmt.Errorf("%w: provider advertises no supported client auth method (advertised %v)", p.Errs.Exchange, p.AuthMethods)
	}
	// The secret joins the form before the request is built, so the body, its
	// length and GetBody (which a 307/308 replay reads) all describe the same
	// form.
	if method == clientauth.Post {
		form.Set("client_secret", secret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("%w: build request: %w", p.Errs.Exchange, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if method == clientauth.Basic {
		// The secret goes in the Authorization header, never in the body.
		// RFC 6749 section 2.3.1 form-encodes both values before base64, and a
		// compliant server decodes them: sent raw, a client id holding ":"
		// splits in the wrong place and a secret holding "+" or "%2F" arrives
		// altered.
		req.SetBasicAuth(url.QueryEscape(p.ClientID), url.QueryEscape(secret))
	}
	return req, nil
}

// decode turns a 2xx token response body into Tokens, refusing an OAuth error
// envelope and a response that lacks what the flow needs.
func decode(p Params, body []byte, secret, authCode, verifier string) (*Tokens, error) {
	// OAuth2 §5.2: an error response uses {"error":"...","error_description":"..."}.
	// Many providers (and the spec) allow it with HTTP 200, so the status check
	// above is not enough. Decode the error fields first and refuse the body
	// if "error" is present. Treat a non-object body (e.g. "null", "[]", a
	// bare string) as an error too: the spec requires an object.
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(body, &probe); err != nil {
		return nil, fmt.Errorf("%w: decode response: invalid JSON object", p.Errs.Exchange)
	}
	if probe == nil {
		return nil, fmt.Errorf("%w: empty response", p.Errs.Exchange)
	}
	if rawErr, ok := probe["error"]; ok {
		var code, desc string
		_ = json.Unmarshal(rawErr, &code)
		if rawDesc, ok := probe["error_description"]; ok {
			_ = json.Unmarshal(rawDesc, &desc)
		}
		// Both strings are the provider's. Clip them to printable text of a
		// bounded size: the message ends up in the caller's logs.
		rawCode, rawDesc := code, desc
		code = safetext.Clip(code, exchangeCodeMaxLen)
		desc = safetext.Clip(desc, exchangeErrorMaxLen)
		// Provider diagnostics must not contain credentials sent in this exchange.
		for _, value := range []string{secret, authCode, verifier} {
			if value != "" && (strings.Contains(rawCode, value) || strings.Contains(rawDesc, value) ||
				strings.Contains(code, value) || strings.Contains(desc, value)) {
				return nil, fmt.Errorf("%w: provider returned an error", p.Errs.Exchange)
			}
		}
		switch {
		case desc != "":
			return nil, fmt.Errorf("%w: provider returned %s: %s", p.Errs.Exchange, code, desc)
		default:
			return nil, fmt.Errorf("%w: provider returned %s", p.Errs.Exchange, code)
		}
	}

	var tok Tokens
	if err := json.Unmarshal(body, &tok); err != nil {
		return nil, fmt.Errorf("%w: decode response: invalid token fields", p.Errs.Exchange)
	}
	if strings.TrimSpace(tok.AccessToken) == "" || tok.TokenType == "" {
		return nil, fmt.Errorf("%w: response missing access_token or token_type", p.Errs.Exchange)
	}
	if tok.ExpiresIn < 0 {
		return nil, fmt.Errorf("%w: response carries a negative expires_in", p.Errs.Exchange)
	}
	tok.ExpiresIn = min(tok.ExpiresIn, expiresInMax)
	// An ID token is required only for an OIDC provider (one that has a JWKS
	// and an issuer check to validate it against). A plain-OAuth2 provider
	// (GitHub, Discord) returns no id_token, since identity comes from UserInfo,
	// so requiring one here would make every such login fail.
	if p.RequireIDToken && tok.IDToken == "" {
		return nil, p.Errs.NoIDToken
	}
	return &tok, nil
}
