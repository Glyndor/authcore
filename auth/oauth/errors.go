package oauth

import "errors"

// Sentinel errors returned by the oauth package.
// Use errors.Is to check for these in calling code.
var (
	// ErrInvalidConfig is returned by New when the Config fails validation
	// (missing client id, endpoints, redirect URL, …).
	//
	// Safety: INTERNAL — a startup/programming error. Treat as a 500.
	ErrInvalidConfig = errors.New("oauth: invalid configuration")

	// ErrExchange is returned when the authorization-code exchange with the
	// provider's token endpoint fails (network error, non-2xx, or an
	// OAuth error response).
	//
	// Safety: INTERNAL — log it; return a generic failure to the user.
	ErrExchange = errors.New("oauth: token exchange failed")

	// ErrNoIDToken is returned by Exchange-derived flows when the provider's
	// response carried no id_token — the provider is not acting as an OIDC
	// provider for this request (e.g. the "openid" scope was dropped).
	//
	// Safety: INTERNAL.
	ErrNoIDToken = errors.New("oauth: response contained no id_token")

	// ErrIDTokenInvalid is returned when the ID token fails validation:
	// bad or unverifiable signature, wrong issuer/audience, expired, an
	// unsupported algorithm, or a nonce mismatch.
	//
	// Safety: INTERNAL — return a generic "unauthorized"; never echo the reason.
	ErrIDTokenInvalid = errors.New("oauth: id token is invalid")

	// ErrJWKS is returned when the provider's signing keys cannot be fetched
	// or parsed.
	//
	// Safety: INTERNAL.
	ErrJWKS = errors.New("oauth: cannot obtain provider signing keys")

	// ErrUserInfo is returned when the userinfo request to a plain-OAuth2
	// provider fails (network error, non-2xx, or undecodable body).
	//
	// Safety: INTERNAL.
	ErrUserInfo = errors.New("oauth: userinfo request failed")

	// ErrNoUserInfo is returned by UserInfo when the provider has no
	// UserInfoURL configured (it is an OIDC provider — use VerifyIDToken).
	//
	// Safety: INTERNAL — a programming error.
	ErrNoUserInfo = errors.New("oauth: no userinfo URL configured")

	// ErrDiscovery is returned by Discover when the OIDC discovery document
	// cannot be fetched or parsed, or its issuer does not match.
	//
	// Safety: INTERNAL.
	ErrDiscovery = errors.New("oauth: OIDC discovery failed")
)
