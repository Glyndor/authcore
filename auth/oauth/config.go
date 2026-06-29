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
	// used to verify ID token signatures.
	JWKSURL string
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
	// Scopes requested at authorization. Defaults to {"openid","email","profile"}.
	// "openid" is always included even if omitted — without it there is no ID token.
	Scopes []string
	// HTTPClient optionally overrides the client used for the token and JWKS
	// requests. Defaults to a client with a 10-second timeout.
	HTTPClient *http.Client
}

// defaultScopes are requested when Config.Scopes is empty.
var defaultScopes = []string{"openid", "email", "profile"}

// applyDefaults fills zero-value fields with safe defaults.
func applyDefaults(cfg Config) Config {
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = defaultScopes
	} else if !containsFold(cfg.Scopes, "openid") {
		// "openid" is mandatory for OIDC; add it rather than silently failing later.
		cfg.Scopes = append([]string{"openid"}, cfg.Scopes...)
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	return cfg
}

// validateConfig returns an error if cfg is missing anything required.
func validateConfig(cfg Config) error {
	if strings.TrimSpace(cfg.ClientID) == "" {
		return fmt.Errorf("client id must not be empty")
	}
	if strings.TrimSpace(cfg.RedirectURL) == "" {
		return fmt.Errorf("redirect URL must not be empty")
	}
	for name, v := range map[string]string{
		"issuer":    cfg.Provider.Issuer,
		"auth URL":  cfg.Provider.AuthURL,
		"token URL": cfg.Provider.TokenURL,
		"JWKS URL":  cfg.Provider.JWKSURL,
	} {
		if strings.TrimSpace(v) == "" {
			return fmt.Errorf("provider %s must not be empty", name)
		}
	}
	return nil
}

// containsFold reports whether list holds s, case-insensitively.
func containsFold(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}
