// Package discovery fetches and validates an OIDC discovery document, binding its issuer exactly to
// the one requested.
package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/Glyndor/authcore/auth/oauth/internal/netguard"
	"github.com/Glyndor/authcore/auth/oauth/internal/redirect"
	"github.com/Glyndor/authcore/auth/oauth/internal/safetext"
	"github.com/Glyndor/authcore/auth/oauth/internal/urlcheck"
)

const (
	discoveryPath     = "/.well-known/openid-configuration"
	discoveryMaxBytes = 1 << 20
)

// Document is the part of an OIDC discovery document the client uses.
type Document struct {
	Issuer      string   `json:"issuer"`
	AuthURL     string   `json:"authorization_endpoint"`
	TokenURL    string   `json:"token_endpoint"`
	JWKSURL     string   `json:"jwks_uri"`
	UserInfoURL string   `json:"userinfo_endpoint"`
	AuthMethods []string `json:"token_endpoint_auth_methods_supported"`
}

// Fetch retrieves and validates the discovery document of issuer. Every failure
// wraps errDiscovery (the public ErrDiscovery sentinel). See oauth.Discover for
// the contract. httpClient may be nil.
func Fetch(ctx context.Context, issuer string, httpClient *http.Client, errDiscovery error) (Document, error) {
	return FetchWith(ctx, issuer, httpClient, errDiscovery, false)
}

// FetchWith is Fetch with the destination policy chosen: allowPrivate lets the
// document advertise endpoints on internal addresses and lets the fetches
// reach them, for an on-premises provider. Without it, an endpoint on a
// private, link-local, unspecified or cloud-metadata address is refused, and
// a loopback endpoint is accepted only when the issuer itself is loopback (a
// developer's local provider vouches for its own machine and nothing else).
func FetchWith(ctx context.Context, issuer string, httpClient *http.Client, errDiscovery error, allowPrivate bool) (Document, error) {
	policy := redirect.Policy{AllowPrivate: allowPrivate}
	if httpClient == nil {
		httpClient = policy.NewClient()
	} else {
		httpClient = policy.Guard(httpClient)
	}
	// Never fetch discovery over plaintext — the whole trust chain (the jwks_uri
	// the ID-token signature hangs on) comes from this document.
	if err := urlcheck.RequireHTTPS("issuer", issuer); err != nil {
		return Document{}, fmt.Errorf("%w: %w", errDiscovery, err)
	}
	trimmed := strings.TrimRight(issuer, "/")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, trimmed+discoveryPath, nil)
	if err != nil {
		return Document{}, fmt.Errorf("%w: build request: %w", errDiscovery, err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return Document{}, fmt.Errorf("%w: %w", errDiscovery, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, discoveryMaxBytes))
	if err != nil {
		return Document{}, fmt.Errorf("%w: read: %w", errDiscovery, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Document{}, fmt.Errorf("%w: status %d", errDiscovery, resp.StatusCode)
	}

	var doc Document
	if err := json.Unmarshal(body, &doc); err != nil {
		return Document{}, fmt.Errorf("%w: decode: %w", errDiscovery, err)
	}

	// The discovered issuer must match the one asked for (OIDC Discovery §4.3).
	// The trimming above only builds the well-known URL. The comparison itself
	// is exact, against the issuer the caller passed in. A document that
	// echoes back the trimmed form (trailing slash dropped) is rejected: the
	// two are not the same value to a comparison that does not know which
	// form was canonicalised when.
	if doc.Issuer != issuer {
		return Document{}, fmt.Errorf("%w: issuer mismatch: document says %s", errDiscovery, safetext.Quote(doc.Issuer))
	}
	if doc.AuthURL == "" || doc.TokenURL == "" || doc.JWKSURL == "" {
		return Document{}, fmt.Errorf("%w: document missing required endpoints", errDiscovery)
	}
	// The endpoints are not constrained to the issuer's origin, so a substituted
	// (or simply misconfigured) document could point them at plaintext hosts —
	// require https on each, and keep them off internal addresses.
	issuerIsLoopback := false
	if u, err := url.Parse(issuer); err == nil {
		issuerIsLoopback = netguard.Loopback(u.Hostname())
	}
	for label, raw := range map[string]string{
		"authorization_endpoint": doc.AuthURL,
		"token_endpoint":         doc.TokenURL,
		"jwks_uri":               doc.JWKSURL,
		"userinfo_endpoint":      doc.UserInfoURL,
	} {
		if raw == "" {
			continue
		}
		if err := urlcheck.RequireHTTPS(label, raw); err != nil {
			return Document{}, fmt.Errorf("%w: %w", errDiscovery, err)
		}
		if allowPrivate {
			continue
		}
		if err := urlcheck.RequireExternal(label, raw, issuerIsLoopback); err != nil {
			return Document{}, fmt.Errorf("%w: %w", errDiscovery, err)
		}
	}

	return doc, nil
}
