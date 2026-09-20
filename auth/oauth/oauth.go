// Package oauth is an OpenID Connect (OIDC) client for authcore — "log in with
// Google / Microsoft / any OIDC provider".
//
// It implements the security-critical mechanics you only get right once:
// Authorization Code flow with PKCE (S256), an unguessable state and nonce, and
// strict ID-token validation (signature against the provider's JWKS, plus
// issuer, audience, expiry, and nonce). It is a client only — authcore does not
// act as an OAuth server. It stores nothing and runs no HTTP server; you own
// the two routes and where you persist the per-request secrets.
//
// # Flow
//
//	mod, _ := oauth.New(auth, oauth.Config{
//	    ClientID: id, ClientSecret: secret,
//	    RedirectURL: "https://app.example.com/callback",
//	    Provider: oauth.Google(),
//	})
//
//	// 1. Start: build the redirect and persist the returned secrets
//	//    (state, nonce, verifier) in a short-lived signed cookie or the session.
//	req, _ := mod.AuthCodeURL()
//	saveToCookie(w, req.State, req.Nonce, req.Verifier)
//	http.Redirect(w, r, req.URL, http.StatusFound)
//
//	// 2. Callback: check state, exchange the code, validate the ID token.
//	if subtle.ConstantTimeCompare([]byte(r.FormValue("state")), []byte(savedState)) != 1 { return /* 400 */ }
//	tok, _ := mod.Exchange(r.Context(), r.FormValue("code"), savedVerifier)
//	claims, err := mod.VerifyIDToken(r.Context(), tok.IDToken, savedNonce)
//	if err != nil { return /* 401 */ }
//	// claims.Subject is the stable user id at this provider; claims.Email etc.
package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/Glyndor/authcore"
)

// Compile-time assertion: *Client must satisfy authcore.Module.
var _ authcore.Module = (*Client)(nil)

// Client is the OIDC client module. Construct one per provider at startup with
// New and share it; it is safe for concurrent use.
type Client struct {
	cfg  Config
	log  authcore.Logger
	http *http.Client
	jwks *jwksCache
}

// New creates an OIDC Client for a single provider.
func New(p authcore.Provider, cfg Config) (*Client, error) {
	cfg = applyDefaults(cfg)
	if err := validateConfig(cfg); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	c := &Client{
		cfg:  cfg,
		log:  p.Logger(),
		http: cfg.HTTPClient,
		jwks: newJWKSCache(cfg.Provider.JWKSURL, cfg.HTTPClient),
	}
	c.log.Info("oauth: module initialised (issuer=%s)", cfg.Provider.Issuer)
	return c, nil
}

// Name returns the module's unique identifier. It implements authcore.Module.
func (c *Client) Name() string { return "oauth" }

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
	state, err := randomURLToken()
	if err != nil {
		return nil, err
	}
	nonce, err := randomURLToken()
	if err != nil {
		return nil, err
	}
	verifier, err := randomURLToken()
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
	q.Set("code_challenge", pkceChallenge(verifier))
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()
	return &AuthRequest{
		URL:      u.String(),
		State:    state,
		Nonce:    nonce,
		Verifier: verifier,
	}, nil
}

// Tokens is the provider's token-endpoint response.
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

// Exchange swaps an authorization code for tokens at the token endpoint, sending
// the PKCE code_verifier. ctx bounds the request.
//
// It returns ErrExchange on a transport error, a non-2xx response, an OAuth
// error response ({"error":"invalid_grant", ...} with HTTP 200), or a 200
// whose body has no access_token/token_type. For an OIDC provider it also
// returns ErrNoIDToken when the response carried no id_token; validate that
// token with VerifyIDToken before trusting it. For a plain-OAuth2 provider
// (no issuer/JWKS) there is no id_token, so call UserInfo.
//
// Client authentication at the token endpoint is chosen from the provider's
// advertised methods: when the discovery document listed "client_secret_basic"
// (or "basic"), the secret is sent in the HTTP Basic header; when only
// "client_secret_post" (or "post") is advertised, it is sent in the form
// body; when the field is absent the OIDC default (Basic) applies. A
// provider that advertises a method this library does not know is refused
// before the round trip.
func (c *Client) Exchange(ctx context.Context, code, verifier string) (*Tokens, error) {
	// Reject empty inputs before talking to the provider. An empty code or
	// verifier would round-trip useless bytes and could mask a wiring bug in
	// the caller (forgot to read the cookie, swapped two variables).
	if code == "" {
		return nil, fmt.Errorf("%w: code must not be empty", ErrExchange)
	}
	if verifier == "" {
		return nil, fmt.Errorf("%w: code_verifier must not be empty", ErrExchange)
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", c.cfg.RedirectURL)
	form.Set("client_id", c.cfg.ClientID)
	form.Set("code_verifier", verifier)

	method := clientAuthMethod(c.cfg.Provider.AuthMethods, c.cfg.ClientSecret != "")
	if method == authMethodNone && c.cfg.ClientSecret != "" {
		return nil, fmt.Errorf("%w: provider advertises no supported client auth method (advertised %v)", ErrExchange, c.cfg.Provider.AuthMethods)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.Provider.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("%w: build request: %w", ErrExchange, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	switch method {
	case authMethodBasic:
		// The secret goes in the Authorization header, never in the body.
		req.SetBasicAuth(c.cfg.ClientID, c.cfg.ClientSecret)
	case authMethodPost:
		form.Set("client_id", c.cfg.ClientID)
		form.Set("client_secret", c.cfg.ClientSecret)
		// Reissue the request body after we mutate the form.
		req.Body, req.ContentLength, err = formBody(form)
		if err != nil {
			return nil, fmt.Errorf("%w: build request body: %w", ErrExchange, err)
		}
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrExchange, err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Cap the response so a hostile or broken endpoint cannot exhaust memory.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("%w: read response: %w", ErrExchange, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%w: status %d", ErrExchange, resp.StatusCode)
	}

	// OAuth2 §5.2: an error response uses {"error":"...","error_description":"..."}.
	// Many providers (and the spec) allow it with HTTP 200, so the status check
	// above is not enough. Decode the error fields first and refuse the body
	// if "error" is present. Treat a non-object body (e.g. "null", "[]", a
	// bare string) as an error too: the spec requires an object.
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(body, &probe); err != nil {
		return nil, fmt.Errorf("%w: decode response: %w", ErrExchange, err)
	}
	if probe == nil {
		return nil, fmt.Errorf("%w: empty response", ErrExchange)
	}
	if rawErr, ok := probe["error"]; ok {
		var code, desc string
		_ = json.Unmarshal(rawErr, &code)
		if rawDesc, ok := probe["error_description"]; ok {
			_ = json.Unmarshal(rawDesc, &desc)
		}
		if len(desc) > exchangeErrorMaxLen {
			desc = desc[:exchangeErrorMaxLen] + "…"
		}
		switch {
		case desc != "":
			return nil, fmt.Errorf("%w: provider returned %s: %s", ErrExchange, code, desc)
		default:
			return nil, fmt.Errorf("%w: provider returned %s", ErrExchange, code)
		}
	}

	var tok Tokens
	if err := json.Unmarshal(body, &tok); err != nil {
		return nil, fmt.Errorf("%w: decode response: %w", ErrExchange, err)
	}
	if tok.AccessToken == "" || tok.TokenType == "" {
		return nil, fmt.Errorf("%w: response missing access_token or token_type", ErrExchange)
	}
	// An ID token is required only for an OIDC provider (one that has a JWKS
	// and an issuer check to validate it against). A plain-OAuth2 provider
	// (GitHub, Discord) returns no id_token, since identity comes from UserInfo,
	// so requiring one here would make every such login fail.
	if c.isOIDC() && tok.IDToken == "" {
		return nil, ErrNoIDToken
	}
	return &tok, nil
}

// isOIDC reports whether the provider issues an ID token (JWKS + issuer
// check), as opposed to a plain-OAuth2 provider identified via UserInfo. The
// single source of truth lives on Config; this just threads it through.
func (c *Client) isOIDC() bool {
	return c.cfg.isOIDC()
}
