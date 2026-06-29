package oauth

import (
	"context"
	"crypto/subtle"
	"fmt"

	gjwt "github.com/golang-jwt/jwt/v5"
)

// idTokenAlgs are the asymmetric signing algorithms an ID token may use. HMAC
// and "none" are intentionally absent: accepting them would enable an
// algorithm-confusion or unsigned-token forgery.
var idTokenAlgs = []string{
	"RS256", "RS384", "RS512",
	"PS256", "PS384", "PS512",
	"ES256", "ES384", "ES512",
}

// IDClaims holds the validated claims of an ID token.
type IDClaims struct {
	// Subject is the "sub" claim — the stable, provider-unique user identifier.
	// Key your account records on (Issuer, Subject), never on email alone.
	Subject string
	// Issuer is the "iss" claim (equals the configured Provider.Issuer).
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
// only), and enforces the issuer, the audience (must contain the client id),
// expiry, and that the "nonce" claim equals the nonce from the matching
// AuthCodeURL request. nonce must be the non-empty value you stored; passing the
// wrong or an empty nonce fails closed.
//
// On any failure it returns ErrIDTokenInvalid (wrapped). Never expose the
// wrapped detail to the end user.
func (c *Client) VerifyIDToken(ctx context.Context, idToken, nonce string) (*IDClaims, error) {
	if nonce == "" {
		return nil, fmt.Errorf("%w: no nonce supplied to verify against", ErrIDTokenInvalid)
	}

	var claims gjwt.MapClaims
	_, err := gjwt.ParseWithClaims(idToken, &claims,
		func(t *gjwt.Token) (any, error) {
			kid, _ := t.Header["kid"].(string)
			return c.jwks.key(ctx, kid)
		},
		gjwt.WithValidMethods(idTokenAlgs),
		gjwt.WithIssuer(c.cfg.Provider.Issuer),
		gjwt.WithAudience(c.cfg.ClientID),
		gjwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrIDTokenInvalid, err)
	}

	// Bind the token to this login: the nonce must match the one we issued.
	got, _ := claims["nonce"].(string)
	if subtle.ConstantTimeCompare([]byte(got), []byte(nonce)) != 1 {
		return nil, fmt.Errorf("%w: nonce mismatch", ErrIDTokenInvalid)
	}

	out := &IDClaims{
		Subject:       stringClaim(claims, "sub"),
		Issuer:        stringClaim(claims, "iss"),
		Audience:      audienceClaim(claims),
		Email:         stringClaim(claims, "email"),
		EmailVerified: boolClaim(claims, "email_verified"),
		Name:          stringClaim(claims, "name"),
		Raw:           claims,
	}
	if out.Subject == "" {
		return nil, fmt.Errorf("%w: missing subject", ErrIDTokenInvalid)
	}
	return out, nil
}

func stringClaim(m gjwt.MapClaims, key string) string {
	s, _ := m[key].(string)
	return s
}

// boolClaim reads a boolean claim, tolerating the string forms ("true"/"false")
// some providers emit for email_verified.
func boolClaim(m gjwt.MapClaims, key string) bool {
	switch v := m[key].(type) {
	case bool:
		return v
	case string:
		return v == "true"
	default:
		return false
	}
}

func audienceClaim(m gjwt.MapClaims) []string {
	switch v := m["aud"].(type) {
	case string:
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, a := range v {
			if s, ok := a.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}
