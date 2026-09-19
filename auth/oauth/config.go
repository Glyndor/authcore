package oauth

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
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
// scopes are used verbatim (an OIDC caller includes "openid"; an OAuth2 caller
// sets the provider's own scopes), so the same constructor serves both flows.
func applyDefaults(cfg Config) Config {
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = defaultScopes
	}
	// A caller supplies a client for its transport, its timeout or its proxy.
	// None of those intentions include turning off the redirect guards, and
	// installing the safe client only when the field is nil is what used to
	// turn them off: safeRedirect is four controls at once, and every one of
	// them was lost on the token, JWKS, userinfo and discovery fetches the
	// moment a caller set this field. The token exchange carries the client
	// secret and receives the ID token, so those are the fetches that least
	// tolerate an unguarded redirect.
	//
	// The copy is deliberate. Forcing the policy onto the caller's own
	// *http.Client would change how that client behaves everywhere else in
	// their program, which is a second surprise rather than a fix. They keep
	// Transport, Timeout and Jar, which is what they supplied it for.
	switch {
	case cfg.HTTPClient == nil:
		cfg.HTTPClient = newSafeHTTPClient()
	default:
		guarded := *cfg.HTTPClient
		guarded.CheckRedirect = safeRedirect
		cfg.HTTPClient = &guarded
	}
	return cfg
}

// newSafeHTTPClient is the default HTTP client for the OAuth fetches. Its
// CheckRedirect closes the SSRF / credential-exfiltration vectors that bare
// redirect-following opens (see safeRedirect). A caller who supplies their own
// HTTPClient owns this policy.
func newSafeHTTPClient() *http.Client {
	return &http.Client{Timeout: 10 * time.Second, CheckRedirect: safeRedirect}
}

// safeRedirect is the redirect policy for every OAuth fetch (token, JWKS,
// userinfo, discovery). It refuses:
//   - more than a few hops,
//   - a downgrade to plaintext http,
//   - a redirect to a loopback / link-local / private host (SSRF to cloud
//     metadata or internal services),
//   - a cross-origin redirect — the token POST replays the client secret on a
//     307/308, so it must never leave the configured host; legitimate OAuth
//     endpoints do not redirect across hosts.
func safeRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return fmt.Errorf("too many redirects")
	}
	if req.URL.Scheme != "https" {
		return fmt.Errorf("refusing redirect to non-https %q", req.URL.Redacted())
	}
	if isPrivateHost(req.URL.Hostname()) {
		return fmt.Errorf("refusing redirect to private host %q", req.URL.Hostname())
	}
	if prev := via[len(via)-1]; req.URL.Host != prev.URL.Host {
		return fmt.Errorf("refusing cross-origin redirect to %q", req.URL.Host)
	}
	return nil
}

// isPrivateHost reports whether host is an IP literal in a loopback, private,
// link-local, or unspecified range. Hostnames (non-literals) return false — the
// scheme and cross-origin checks still apply, and the initial endpoint was
// https-validated.
func isPrivateHost(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified()
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

	// OIDC needs the JWKS to verify signatures, plus an issuer to check — either
	// a fixed Issuer or an IssuerValidator predicate (multi-tenant).
	oidc := cfg.Provider.JWKSURL != "" && (cfg.Provider.Issuer != "" || cfg.IssuerValidator != nil)
	oauth2 := cfg.Provider.UserInfoURL != ""
	if !oidc && !oauth2 {
		return fmt.Errorf("provider must supply either JWKS + (issuer or IssuerValidator) for OIDC, or a userinfo URL for OAuth2")
	}
	// A JWKS without any issuer check (no fixed Issuer and no validator), or an
	// Issuer without a JWKS, is a half-configured OIDC provider — flag it rather
	// than silently dropping verification.
	if !oauth2 {
		hasIssuerCheck := cfg.Provider.Issuer != "" || cfg.IssuerValidator != nil
		if hasIssuerCheck != (cfg.Provider.JWKSURL != "") {
			return fmt.Errorf("OIDC provider needs both a JWKS URL and an issuer (fixed or IssuerValidator)")
		}
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
		if err := requireHTTPS(label, raw); err != nil {
			return err
		}
	}
	return nil
}

// requireHTTPS rejects a URL whose scheme is not https. Plain http is allowed
// only for an explicit loopback host (local development), and that is the loud
// exception — the secure transport is the default everywhere else.
func requireHTTPS(label, raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%s is not a valid URL: %w", label, err)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if isLoopbackHost(u.Hostname()) {
			return nil
		}
	}
	return fmt.Errorf("%s must use https (got %q in %q)", label, u.Scheme, raw)
}

// isLoopbackHost reports whether host is a loopback address (dev-only http).
func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	// Match the whole loopback range rather than the two literals people
	// usually type. 127.0.0.0/8 is all loopback, and a development server
	// bound to 127.0.0.2 to dodge a port collision is as local as 127.0.0.1.
	// Failing to recognise it refused the documented plaintext exception, so
	// this was a usability gap rather than a hole, but the definition should
	// be the one the standard library already has.
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
