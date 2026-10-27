package oauth

import (
	"context"

	"github.com/Glyndor/authcore/auth/oauth/internal/exchange"
)

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
	if !c.built() {
		return nil, errNotBuilt
	}
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
