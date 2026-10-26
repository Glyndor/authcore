package oauth

import (
	"context"
	"fmt"

	"github.com/Glyndor/authcore/auth/oauth/internal/idtoken"
)

// IDClaims holds the validated claims of an ID token.
type IDClaims struct {
	// Subject is the "sub" claim — the stable, provider-unique user identifier.
	// Key your account records on (Issuer, Subject), never on email alone.
	Subject string
	// Issuer is the "iss" claim. When no IssuerValidator is configured
	// the issuer always equals the configured Provider.Issuer, because
	// VerifyIDToken rejects tokens whose iss does not match it. When
	// IssuerValidator is configured (multi-tenant providers such as
	// Azure AD "common") the issuer is whatever string the validator
	// accepted, which need not equal Provider.Issuer. Provider.Issuer
	// is ignored on the verification path in that case.
	Issuer string
	// Audience is the "aud" claim (contains the configured ClientID).
	Audience []string
	// Email is the "email" claim, if present.
	Email string
	// EmailVerified is the "email_verified" claim. Do not treat an unverified
	// email as proof of address ownership.
	EmailVerified bool
	// Name is the "name" claim, if present.
	Name string
	// Raw exposes every claim for provider-specific fields not surfaced above.
	Raw map[string]any
}

// VerifyIDToken validates an ID token and returns its claims.
//
// It verifies the signature against the provider's JWKS (asymmetric algorithms
// only), and enforces the issuer, the issuer the signing key is restricted to
// when its JWK carries an "issuer" member (completing a "{tenantid}" template
// with the token's "tid"), the audience (must equal the client id and no
// other), "azp" (must equal the client id when present), a numeric "iat",
// expiry, and that the "nonce" claim equals the nonce from the matching
// AuthCodeURL request. nonce must be the non-empty
// value you stored; passing the wrong or an empty nonce fails closed.
//
// A token that lists critical header extensions ("crit") is refused, since
// none is understood. The base64 spelling of a token is canonical, but an
// ECDSA (ES*) signature has a second valid encoding of the same token, so do
// not use the token string as the key of a blocklist or replay cache; key it
// on the nonce or the "jti" claim.
//
// On any failure it returns ErrIDTokenInvalid (wrapped). Never expose the
// wrapped detail to the end user.
func (c *Client) VerifyIDToken(ctx context.Context, idToken, nonce string) (*IDClaims, error) {
	if !c.built() {
		return nil, fmt.Errorf("%w: client not initialised, use oauth.New", ErrIDTokenInvalid)
	}
	// Refuse to verify against a provider that is not configured for OIDC.
	// Doing so would either skip the iss check (if we passed WithIssuer(""))
	// or trust every JWKS-signer in the world without binding tokens to a
	// provider. Plain-OAuth2 callers use UserInfo instead.
	if !c.cfg.isOIDC() {
		return nil, fmt.Errorf("%w: provider is not configured for OIDC", ErrIDTokenInvalid)
	}
	validator := c.cfg.IssuerValidator
	if validator == nil {
		validator = c.cfg.Provider.IssuerValidator
	}
	claims, err := idtoken.Verify(ctx, idtoken.Params{
		ClientID:  c.cfg.ClientID,
		Issuer:    c.cfg.Provider.Issuer,
		Validator: validator,
		Keys:      c.jwks,
		Invalid:   ErrIDTokenInvalid,
	}, idToken, nonce)
	if err != nil {
		return nil, err
	}
	return &IDClaims{
		Subject:       claims.Subject,
		Issuer:        claims.Issuer,
		Audience:      claims.Audience,
		Email:         claims.Email,
		EmailVerified: claims.EmailVerified,
		Name:          claims.Name,
		Raw:           claims.Raw,
	}, nil
}
