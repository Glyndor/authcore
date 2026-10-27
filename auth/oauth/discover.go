package oauth

import (
	"context"
	"net/http"

	"github.com/Glyndor/authcore/auth/oauth/internal/discovery"
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

// DiscoverOption changes how Discover treats the endpoints a discovery
// document advertises.
type DiscoverOption func(*discoverOptions)

type discoverOptions struct{ allowPrivate bool }

// AllowPrivateNetwork lets the document advertise endpoints on private,
// link-local or otherwise internal addresses, and lets a client built by
// Discover reach them. Pass it only for an on-premises provider whose
// endpoints really live on an internal network; see Config.AllowPrivateNetwork.
func AllowPrivateNetwork() DiscoverOption {
	return func(o *discoverOptions) { o.allowPrivate = true }
}
