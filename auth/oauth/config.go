package oauth

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Provider describes an OIDC provider's endpoints. Use a preset (Google,
// Microsoft) or fill it in from the provider's discovery document.
type Provider struct {
	// Issuer is the exact "iss" value the provider stamps into its ID tokens.
	// It is enforced on verification, so it must match byte-for-byte.
	Issuer string
	// AuthURL is the authorization endpoint the user is redirected to.
	AuthURL string
	// TokenURL is the token endpoint where the code is exchanged.
	TokenURL string
	// JWKSURL is the endpoint serving the provider's signing keys (JWKS),
	// used to verify ID token signatures. Required for OIDC providers (those
	// that issue an ID token); leave empty for a plain-OAuth2 provider.
	JWKSURL string

	// UserInfoURL is the profile endpoint for a plain-OAuth2 provider that does
	// not issue an ID token (e.g. GitHub, Discord). When set, identity comes
	// from UserInfo(accessToken) instead of VerifyIDToken. Optional for OIDC
	// providers, which carry identity in the ID token.
	UserInfoURL string
}

// Config configures an OIDC client for a single provider.
type Config struct {
	// ClientID is the OAuth client identifier registered with the provider.
	ClientID string
	// ClientSecret is the client secret. Leave empty for a public client that
	// relies on PKCE alone (PKCE is always used regardless).
	ClientSecret string
	// RedirectURL is the callback URL registered with the provider; it must
	// match exactly.
	RedirectURL string
	// Provider holds the provider endpoints.
	Provider Provider
	// Scopes requested at authorization. When empty, defaults to the OIDC set
	// {"openid","email","profile"}. When you set it, it is used verbatim — for
	// an OIDC provider include "openid" yourself (without it there is no ID
	// token); for a plain-OAuth2 provider set that provider's own scopes
	// (e.g. GitHub's "read:user user:email").
	Scopes []string
	// HTTPClient optionally overrides the client used for the token and JWKS
	// requests. Defaults to a client with a 10-second timeout.
	HTTPClient *http.Client
}

// defaultScopes are requested when Config.Scopes is empty.
var defaultScopes = []string{"openid", "email", "profile"}

// applyDefaults fills zero-value fields with safe defaults. Caller-supplied
// scopes are used verbatim (an OIDC caller includes "openid"; an OAuth2 caller
// sets the provider's own scopes), so the same constructor serves both flows.
func applyDefaults(cfg Config) Config {
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = defaultScopes
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	return cfg
}

// validateConfig returns an error if cfg is missing anything required.
//
// Every provider needs the authorization and token endpoints. Identity then
// comes from one of two sources: an OIDC provider supplies Issuer + JWKSURL
// (the ID token is validated against them), a plain-OAuth2 provider supplies
// UserInfoURL. A provider with neither cannot identify the user and is rejected.
func validateConfig(cfg Config) error {
	if strings.TrimSpace(cfg.ClientID) == "" {
		return fmt.Errorf("client id must not be empty")
	}
	if strings.TrimSpace(cfg.RedirectURL) == "" {
		return fmt.Errorf("redirect URL must not be empty")
	}
	if strings.TrimSpace(cfg.Provider.AuthURL) == "" {
		return fmt.Errorf("provider auth URL must not be empty")
	}
	if strings.TrimSpace(cfg.Provider.TokenURL) == "" {
		return fmt.Errorf("provider token URL must not be empty")
	}

	oidc := cfg.Provider.Issuer != "" && cfg.Provider.JWKSURL != ""
	oauth2 := cfg.Provider.UserInfoURL != ""
	if !oidc && !oauth2 {
		return fmt.Errorf("provider must supply either issuer+JWKS (OIDC) or a userinfo URL (OAuth2)")
	}
	// A half-configured OIDC provider (only one of issuer/JWKS) with no userinfo
	// fallback is a mistake — flag it rather than silently dropping ID-token
	// verification.
	if !oauth2 && (cfg.Provider.Issuer == "") != (cfg.Provider.JWKSURL == "") {
		return fmt.Errorf("OIDC provider needs both issuer and JWKS URL")
	}
	return nil
}
