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
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/oauth/internal/discovery"
	"github.com/Glyndor/authcore/auth/oauth/internal/exchange"
	"github.com/Glyndor/authcore/auth/oauth/internal/jwks"
	"github.com/Glyndor/authcore/auth/oauth/internal/pkce"
	"github.com/Glyndor/authcore/auth/oauth/internal/userinfo"
)

// Compile-time assertion: *Client must satisfy authcore.Module.
var _ authcore.Module = (*Client)(nil)

// Client is the OIDC client module. Construct one per provider at startup with
// New and share it; it is safe for concurrent use.
type Client struct {
	cfg  Config
	log  authcore.Logger
	http *http.Client
	jwks *jwks.Cache
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
		jwks: jwks.New(cfg.Provider.JWKSURL, cfg.HTTPClient, jwks.Errors{Fetch: ErrJWKS, Stale: ErrJWKSStale}),
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

// Tokens is the provider's token-endpoint response.
type Tokens struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	ExpiresIn    int    `json:"expires_in"`
}

// Exchange swaps an authorization code for tokens at the token endpoint, sending
// the PKCE code_verifier. ctx bounds the request.
//
// It returns ErrExchange on any of: an empty code or code_verifier
// argument, a failure to build the HTTP request, a transport error
// from c.http.Do, a read error on the response body, a non-2xx status,
// a 200 whose body is not a JSON object, a 200 whose JSON object
// carries an "error" field ({"error":"invalid_grant", ...}), a 200
// whose JSON fails to decode as Tokens, or a 200 that decodes but is
// missing access_token or token_type. The wrap message names which
// step failed. For an OIDC provider it also returns ErrNoIDToken when
// the response carried no id_token; validate that token with
// VerifyIDToken before trusting it. For a plain-OAuth2 provider
// (no issuer/JWKS) there is no id_token, so call UserInfo.
//
// Client authentication at the token endpoint is chosen from the provider's
// advertised methods: when the discovery document listed "client_secret_basic"
// (or "basic"), the secret is sent in the HTTP Basic header; when only
// "client_secret_post" (or "post") is advertised, it is sent in the form
// body; when the field is absent it is sent in the form body too, which is
// what every hand-configured Provider relied on before the methods were
// read (the OIDC default would be Basic). A provider that advertises only
// methods this library does not know is refused before the round trip.
func (c *Client) Exchange(ctx context.Context, code, verifier string) (*Tokens, error) {
	tok, err := exchange.Do(ctx, c.http, exchange.Params{
		TokenURL:       c.cfg.Provider.TokenURL,
		ClientID:       c.cfg.ClientID,
		RedirectURL:    c.cfg.RedirectURL,
		Secret:         c.cfg.ClientSecret,
		SecretFunc:     c.cfg.ClientSecretFunc,
		AuthMethods:    c.cfg.Provider.AuthMethods,
		RequireIDToken: c.isOIDC(),
		Errs:           exchange.Errors{Exchange: ErrExchange, NoIDToken: ErrNoIDToken},
	}, code, verifier)
	if err != nil {
		return nil, err
	}
	out := Tokens(*tok)
	return &out, nil
}

// isOIDC reports whether the provider issues an ID token (JWKS + issuer
// check), as opposed to a plain-OAuth2 provider identified via UserInfo. The
// single source of truth lives on Config; this just threads it through.
func (c *Client) isOIDC() bool {
	return c.cfg.isOIDC()
}

// Discover builds a Provider from an OIDC issuer's discovery document, instead
// of hardcoding endpoints. Pass the issuer URL (e.g.
// "https://accounts.google.com", an Auth0/Okta tenant, a Keycloak realm) and
// the authorization, token, JWKS and userinfo endpoints are read from the
// provider itself — always current, never a stale constant.
//
// It enforces that the document's "issuer" equals the requested issuer (per
// OpenID Connect Discovery), so a substituted discovery document cannot point
// the client at attacker endpoints under a victim's name. ctx bounds the fetch;
// httpClient is optional (a 10-second-timeout client is used when nil).
// A supplied client is copied, with the library's redirect rule applied before
// the caller's CheckRedirect. The original client is not modified.
//
// The endpoints in the document must be https and must not sit on an internal
// address (private, link-local, unspecified, cloud metadata), and neither may
// anything the fetches are redirected to or resolve to; a loopback issuer, a
// local development provider, may use loopback endpoints. A document that
// carries credentials in a URL is refused. An on-premises provider whose
// endpoints really are internal needs the AllowPrivateNetwork option. See
// Config.AllowPrivateNetwork for how the connection check treats a client you
// supply.
//
//	p, err := oauth.Discover(ctx, "https://accounts.google.com", nil)
//	if err != nil { ... }
//	mod, _ := oauth.New(auth, oauth.Config{ClientID: id, RedirectURL: cb, Provider: p})
func Discover(ctx context.Context, issuer string, httpClient *http.Client, opts ...DiscoverOption) (Provider, error) {
	var o discoverOptions
	for _, opt := range opts {
		opt(&o)
	}
	doc, err := discovery.FetchWith(ctx, issuer, httpClient, ErrDiscovery, o.allowPrivate)
	if err != nil {
		return Provider{}, err
	}
	return Provider{
		Issuer:      doc.Issuer,
		AuthURL:     doc.AuthURL,
		TokenURL:    doc.TokenURL,
		JWKSURL:     doc.JWKSURL,
		UserInfoURL: doc.UserInfoURL,
		AuthMethods: doc.AuthMethods,
	}, nil
}

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
	return userinfo.Fetch(ctx, c.http, c.cfg.Provider.UserInfoURL, accessToken, ErrUserInfo)
}
