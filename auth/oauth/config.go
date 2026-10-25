package oauth

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/Glyndor/authcore/auth/oauth/internal/redirect"
	"github.com/Glyndor/authcore/auth/oauth/internal/urlcheck"
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

	// AuthMethods lists the client authentication methods the provider
	// advertises for its token endpoint, drawn from the discovery document's
	// token_endpoint_auth_methods_supported. Exchange uses it to pick the
	// method it sends: Basic when advertised, Post when only Post is
	// advertised, and Post when the field is absent (see clientAuthMethod).
	// Leave empty for a hand-built Provider, which behaves like an absent
	// discovery document.
	AuthMethods []string

	// IssuerValidator, when set, is used by VerifyIDToken to approve an
	// issuer instead of comparing it byte-for-byte to Issuer. It is set by
	// presets whose providers publish more than one valid issuer spelling
	// (Google today); leave it nil for a Provider with a single authoritative
	// Issuer. The predicate sees the raw "iss" claim value from the token,
	// without scheme normalisation, which keeps the comparison tight.
	IssuerValidator func(issuer string) bool

	// DefaultScopes is the scope set requested when Config.Scopes is empty.
	// Presets set it for providers whose scopes differ from the OIDC default
	// ("openid email profile"). A caller-supplied Config.Scopes wins, so a
	// caller can still narrow the set; Config.Scopes empty and a nil
	// DefaultScopes falls back to the OIDC default set.
	DefaultScopes []string
}

// Config configures an OIDC client for a single provider.
type Config struct {
	// ClientID is the OAuth client identifier registered with the provider.
	ClientID string
	// ClientSecret is the client secret. Leave empty for a public client that
	// relies on PKCE alone (PKCE is always used regardless).
	ClientSecret string
	// ClientSecretFunc returns the client secret on demand. It is called once
	// per Exchange, with the request's own context, and must be safe for
	// concurrent use. Setting ClientSecretFunc is mutually exclusive with
	// ClientSecret: New refuses a Config that sets both.
	//
	// AppleClientSecret returns a function for this field that signs a
	// five-minute secret per call.
	ClientSecretFunc func(ctx context.Context) (string, error)
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

	// IssuerValidator optionally replaces the default exact "iss" match with a
	// predicate. It is nil by default (exact match against Provider.Issuer).
	//
	// Set it for a multi-tenant provider whose tokens carry a per-tenant issuer
	// that no single string can match — e.g. Azure AD "common", where each
	// user's token issuer contains their own tenant id (see AzureMultiTenantIssuer).
	// When set, Provider.Issuer is ignored for verification and VerifyIDToken
	// accepts a token whose iss the function approves.
	//
	// Returning true for an issuer means trusting every token it mints, so keep
	// the predicate tight (a fixed pattern), and if you must restrict to certain
	// tenants, additionally check the "tid" claim via IDClaims.Raw.
	IssuerValidator func(issuer string) bool
}

// defaultScopes are requested when Config.Scopes is empty.
var defaultScopes = []string{"openid", "email", "profile"}

// applyDefaults fills zero-value fields with safe defaults. Caller-supplied
// scopes are cloned so later mutation of the caller's slice cannot change the
// authorization URL the client produces; an OIDC caller includes "openid",
// an OAuth2 caller sets the provider's own scopes, so the same constructor
// serves both flows.
//
// When Config.Scopes is empty the OIDC default set is used. A preset whose
// Provider.DefaultScopes is non-empty overrides that with its own scope list,
// and Apple uses "openid email name" in place of "openid email profile".
// Both paths clone the source slice, so a caller that mutates the slice on
// their side after New cannot change the URL a built client produces.
func applyDefaults(cfg Config) Config {
	if len(cfg.Scopes) == 0 {
		if len(cfg.Provider.DefaultScopes) > 0 {
			cfg.Scopes = append([]string(nil), cfg.Provider.DefaultScopes...)
		} else {
			cfg.Scopes = append([]string(nil), defaultScopes...)
		}
	} else {
		cfg.Scopes = append([]string(nil), cfg.Scopes...)
	}
	// Same for the advertised auth methods: Exchange reads them on every
	// call, so a caller mutating its slice after New would change how an
	// existing client authenticates, and race with a concurrent Exchange.
	cfg.Provider.AuthMethods = append([]string(nil), cfg.Provider.AuthMethods...)
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = redirect.NewClient()
	} else {
		cfg.HTTPClient = redirect.GuardClient(cfg.HTTPClient)
	}
	return cfg
}

// isOIDC reports whether the provider issues ID tokens: it must supply a JWKS
// endpoint to verify signatures against, and an issuer check to bind tokens to
// the provider (either a fixed Provider.Issuer or an IssuerValidator for
// multi-tenant setups). A provider that lacks either is plain-OAuth2 and
// identifies users via UserInfo instead.
//
// The single source of truth for the OIDC/OAuth2 distinction: validateConfig,
// Exchange, and VerifyIDToken all use this predicate.
func (c Config) isOIDC() bool {
	return c.Provider.JWKSURL != "" && (c.Provider.Issuer != "" || c.IssuerValidator != nil)
}

// validateConfig returns an error if cfg is missing anything required.
//
// Every provider needs the authorization and token endpoints. Identity then
// comes from one of two sources: an OIDC provider supplies JWKSURL + an issuer
// check (the ID token is validated against them), a plain-OAuth2 provider
// supplies UserInfoURL. A provider with neither cannot identify the user and
// is rejected. A provider with a JWKS but no issuer check is half-configured
// OIDC and is also rejected: validating a signature without checking the
// issuer means the client would accept any token the JWKS signer mints, which
// is not what the caller asked for.
func validateConfig(cfg Config) error {
	if strings.TrimSpace(cfg.ClientID) == "" {
		return fmt.Errorf("client id must not be empty")
	}
	if cfg.ClientSecret != "" && cfg.ClientSecretFunc != nil {
		return fmt.Errorf("ClientSecret and ClientSecretFunc are mutually exclusive: set one or the other")
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

	oidc := cfg.isOIDC()
	oauth2 := cfg.Provider.UserInfoURL != ""
	if !oidc && !oauth2 {
		return fmt.Errorf("provider must supply either JWKS + (issuer or IssuerValidator) for OIDC, or a userinfo URL for OAuth2")
	}
	// A JWKS without an issuer check is half-configured OIDC. Reject regardless
	// of whether UserInfoURL is also set, so the caller cannot silently end up
	// verifying signatures while skipping the iss check.
	if cfg.Provider.JWKSURL != "" && cfg.Provider.Issuer == "" && cfg.IssuerValidator == nil {
		return fmt.Errorf("OIDC provider needs both a JWKS URL and an issuer (fixed or IssuerValidator)")
	}

	// Every endpoint and the redirect must be https (loopback excepted), so a
	// MITM cannot intercept the code/token exchange or substitute the JWKS.
	for label, raw := range map[string]string{
		"redirect URL":          cfg.RedirectURL,
		"provider auth URL":     cfg.Provider.AuthURL,
		"provider token URL":    cfg.Provider.TokenURL,
		"provider JWKS URL":     cfg.Provider.JWKSURL,
		"provider userinfo URL": cfg.Provider.UserInfoURL,
		"provider issuer":       cfg.Provider.Issuer,
	} {
		if raw == "" {
			continue
		}
		if err := urlcheck.RequireHTTPS(label, raw); err != nil {
			return err
		}
	}
	// The authorization URL is the one the user is sent to. A fragment on it
	// would land every parameter inside the fragment instead of the query
	// string, which no OIDC server reads. Refuse it here rather than discover
	// the misconfiguration on the first login attempt.
	if err := urlcheck.RequireNoFragment("provider auth URL", cfg.Provider.AuthURL); err != nil {
		return err
	}
	return nil
}
