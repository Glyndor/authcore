package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	discoveryPath     = "/.well-known/openid-configuration"
	discoveryMaxBytes = 1 << 20
)

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
//
//	p, err := oauth.Discover(ctx, "https://accounts.google.com", nil)
//	if err != nil { ... }
//	mod, _ := oauth.New(auth, oauth.Config{ClientID: id, RedirectURL: cb, Provider: p})
func Discover(ctx context.Context, issuer string, httpClient *http.Client) (Provider, error) {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	// Never fetch discovery over plaintext — the whole trust chain (the jwks_uri
	// the ID-token signature hangs on) comes from this document.
	if err := requireHTTPS("issuer", issuer); err != nil {
		return Provider{}, fmt.Errorf("%w: %w", ErrDiscovery, err)
	}
	trimmed := strings.TrimRight(issuer, "/")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, trimmed+discoveryPath, nil)
	if err != nil {
		return Provider{}, fmt.Errorf("%w: build request: %w", ErrDiscovery, err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return Provider{}, fmt.Errorf("%w: %w", ErrDiscovery, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, discoveryMaxBytes))
	if err != nil {
		return Provider{}, fmt.Errorf("%w: read: %w", ErrDiscovery, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Provider{}, fmt.Errorf("%w: status %d", ErrDiscovery, resp.StatusCode)
	}

	var doc struct {
		Issuer   string `json:"issuer"`
		Auth     string `json:"authorization_endpoint"`
		Token    string `json:"token_endpoint"`
		JWKS     string `json:"jwks_uri"`
		UserInfo string `json:"userinfo_endpoint"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return Provider{}, fmt.Errorf("%w: decode: %w", ErrDiscovery, err)
	}

	// The discovered issuer must match the one asked for (OIDC Discovery §4.3).
	if doc.Issuer != issuer && doc.Issuer != trimmed {
		return Provider{}, fmt.Errorf("%w: issuer mismatch: document says %q", ErrDiscovery, doc.Issuer)
	}
	if doc.Auth == "" || doc.Token == "" || doc.JWKS == "" {
		return Provider{}, fmt.Errorf("%w: document missing required endpoints", ErrDiscovery)
	}
	// The endpoints are not constrained to the issuer's origin, so a substituted
	// (or simply misconfigured) document could point them at plaintext hosts —
	// require https on each.
	for label, raw := range map[string]string{
		"authorization_endpoint": doc.Auth,
		"token_endpoint":         doc.Token,
		"jwks_uri":               doc.JWKS,
		"userinfo_endpoint":      doc.UserInfo,
	} {
		if raw == "" {
			continue
		}
		if err := requireHTTPS(label, raw); err != nil {
			return Provider{}, fmt.Errorf("%w: %w", ErrDiscovery, err)
		}
	}

	return Provider{
		Issuer:      doc.Issuer,
		AuthURL:     doc.Auth,
		TokenURL:    doc.Token,
		JWKSURL:     doc.JWKS,
		UserInfoURL: doc.UserInfo,
	}, nil
}
