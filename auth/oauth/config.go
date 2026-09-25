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

	// AuthMethods lists the client authentication methods the provider
	// advertises for its token endpoint, drawn from the discovery document's
	// token_endpoint_auth_methods_supported. Exchange uses it to pick the
	// method it sends: Basic when advertised, Post when only Post is
	// advertised, and none when the field is absent (see clientAuthMethod, the
	// OIDC default). Leave empty for a hand-built Provider, which behaves
	// like an absent discovery document.
	AuthMethods []string

	// IssuerValidator, when set, is used by VerifyIDToken to approve an
	// issuer instead of comparing it byte-for-byte to Issuer. It is set by
	// presets whose providers publish more than one valid issuer spelling
	// (Google today); leave it nil for a Provider with a single authoritative
	// Issuer. The predicate sees the raw "iss" claim value from the token,
	// without scheme normalisation, which keeps the comparison tight.
	IssuerValidator func(issuer string) bool
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
// scopes are cloned so later mutation of the caller's slice cannot change the
// authorization URL the client produces; an OIDC caller includes "openid",
// an OAuth2 caller sets the provider's own scopes, so the same constructor
// serves both flows.
func applyDefaults(cfg Config) Config {
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = append([]string(nil), defaultScopes...)
	} else {
		cfg.Scopes = append([]string(nil), cfg.Scopes...)
	}
	switch {
	case cfg.HTTPClient == nil:
		cfg.HTTPClient = newSafeHTTPClient()
	default:
		cfg.HTTPClient = guardClient(cfg.HTTPClient)
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

// guardClient returns a shallow copy of non-nil c without mutating c. The
// library's redirect rule applies first; the caller's CheckRedirect still
// applies to redirects that safeRedirect accepts. Transport, Timeout and Jar
// are preserved.
//
// A caller-supplied client whose Timeout is zero would remove the bound the
// default client carries, since http.Client.Do on a zero-timeout client
// blocks indefinitely on a hung provider. The library's 10-second default is
// reapplied in that case, so the supplied client cannot quietly disable the
// bound by clearing the field.
func guardClient(c *http.Client) *http.Client {
	// Copy the client; replacing its callback previously discarded caller refusals.
	guarded := *c
	// checkRedirect preserves the caller's callback at the time of the copy.
	checkRedirect := c.CheckRedirect
	guarded.CheckRedirect = safeRedirect
	if checkRedirect != nil {
		guarded.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if err := safeRedirect(req, via); err != nil {
				return err
			}
			return checkRedirect(req, via)
		}
	}
	if guarded.Timeout == 0 {
		guarded.Timeout = 10 * time.Second
	}
	return &guarded
}

// newSafeHTTPClient returns the default HTTP client for OAuth fetches, with a
// 10-second timeout and safeRedirect as its redirect policy. Supplied clients
// receive the same policy through guardClient before their own redirect rule.
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
	prev := via[len(via)-1]
	if !sameOrigin(prev.URL, req.URL) {
		return fmt.Errorf("refusing cross-origin redirect to %q", req.URL.Host)
	}
	return nil
}

// sameOrigin reports whether a and b refer to the same scheme/host/port. It
// compares the host case-insensitively (Hostnames are case-insensitive per
// RFC 3986 §3.2.2) and the port by its effective value: an unset or default
// port is treated as the scheme's default, so https://provider.example and
// https://provider.example:443 are the same origin.
func sameOrigin(a, b *url.URL) bool {
	if a.Scheme != b.Scheme {
		return false
	}
	if !strings.EqualFold(a.Hostname(), b.Hostname()) {
		return false
	}
	return effectivePort(a) == effectivePort(b)
}

// effectivePort returns port as a string, defaulting to the scheme's standard
// port when not set. Comparing two unspecified ports this way means
// https://provider.example and https://provider.example:443 do not look like
// a cross-origin move and stay on the same origin.
func effectivePort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	switch u.Scheme {
	case "https":
		return "443"
	case "http":
		return "80"
	}
	return ""
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
		if err := requireHTTPS(label, raw); err != nil {
			return err
		}
	}
	// The authorization URL is the one the user is sent to. A fragment on it
	// would land every parameter inside the fragment instead of the query
	// string, which no OIDC server reads. Refuse it here rather than discover
	// the misconfiguration on the first login attempt.
	if err := requireNoFragment("provider auth URL", cfg.Provider.AuthURL); err != nil {
		return err
	}
	return nil
}

// requireNoFragment rejects a URL whose fragment is non-empty. The OIDC
// authorization endpoint is expected to consume query parameters; anything
// after '#' never reaches the server.
func requireNoFragment(label, raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		// Parsing failures are reported by requireHTTPS, which runs first.
		return nil
	}
	if u.Fragment != "" || strings.Contains(raw, "#") {
		return fmt.Errorf("%s must not carry a fragment: %q", label, raw)
	}
	return nil
}

// requireHTTPS rejects a URL whose scheme is not https. Plain http is allowed
// only for an explicit loopback host (local development), and that is the loud
// exception — the secure transport is the default everywhere else.
//
// Opaque URLs (https:opaque, https:?query) and https URLs with no host
// (https:///path) parse without erroring but cannot be reached. They were
// accepted by validation and only failed later, when the fetch ran, so the
// caller had no signal that the config was unworkable. Both are refused here.
func requireHTTPS(label, raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%s is not a valid URL: %w", label, err)
	}
	if u.Opaque != "" {
		return fmt.Errorf("%s is opaque, not a hierarchical URL: %q", label, raw)
	}
	if u.Host == "" {
		return fmt.Errorf("%s has no host, not a hierarchical URL: %q", label, raw)
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
