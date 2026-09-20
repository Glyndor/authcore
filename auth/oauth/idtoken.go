package oauth

import (
	"context"
	"crypto/subtle"
	"encoding/json"
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

// maxIDTokenLen caps an ID token before parsing. Real ID tokens are a few KiB
// (larger than an access token because of profile claims and an RSA signature);
// 16 KiB is generous while refusing a multi-megabyte string that would force
// base64+JSON work before the signature is checked.
const maxIDTokenLen = 16 * 1024

// VerifyIDToken validates an ID token and returns its claims.
//
// It verifies the signature against the provider's JWKS (asymmetric algorithms
// only), and enforces the issuer, the audience (must equal the client id and
// no other), a numeric "iat", expiry, and that the "nonce" claim equals the
// nonce from the matching AuthCodeURL request. nonce must be the non-empty
// value you stored; passing the wrong or an empty nonce fails closed.
//
// On any failure it returns ErrIDTokenInvalid (wrapped). Never expose the
// wrapped detail to the end user.
func (c *Client) VerifyIDToken(ctx context.Context, idToken, nonce string) (*IDClaims, error) {
	// Refuse to verify against a provider that is not configured for OIDC.
	// Doing so would either skip the iss check (if we passed WithIssuer(""))
	// or trust every JWKS-signer in the world without binding tokens to a
	// provider. Plain-OAuth2 callers use UserInfo instead.
	if !c.cfg.isOIDC() {
		return nil, fmt.Errorf("%w: provider is not configured for OIDC", ErrIDTokenInvalid)
	}
	if nonce == "" {
		return nil, fmt.Errorf("%w: no nonce supplied to verify against", ErrIDTokenInvalid)
	}
	if len(idToken) > maxIDTokenLen {
		return nil, fmt.Errorf("%w: token too large", ErrIDTokenInvalid)
	}

	opts := []gjwt.ParserOption{
		gjwt.WithValidMethods(idTokenAlgs),
		gjwt.WithAudience(c.cfg.ClientID),
		gjwt.WithExpirationRequired(),
		gjwt.WithIssuedAt(),
	}
	// Exact issuer match unless a validator is configured (multi-tenant or
	// preset-supplied), in which case the issuer is checked by the predicate
	// after parsing. When no validator is set the fixed issuer is non-empty
	// by construction (validateConfig rejects a JWKS without an issuer
	// check); the guard prevents a future caller from slipping an empty
	// issuer past us, because golang-jwt v5's WithIssuer("") silently
	// disables the iss check.
	//
	// Two validators exist: Config.IssuerValidator (caller-supplied, used
	// for multi-tenant Azure-style setups) and Provider.IssuerValidator
	// (preset-supplied, used by Google to accept two issuer spellings).
	// Either approves the iss claim; the fixed Provider.Issuer is ignored
	// when either is set.
	validator := c.cfg.IssuerValidator
	if validator == nil {
		validator = c.cfg.Provider.IssuerValidator
	}
	if validator == nil {
		if c.cfg.Provider.Issuer == "" {
			return nil, fmt.Errorf("%w: no issuer configured", ErrIDTokenInvalid)
		}
		opts = append(opts, gjwt.WithIssuer(c.cfg.Provider.Issuer))
	}

	var claims gjwt.MapClaims
	_, err := gjwt.ParseWithClaims(idToken, &claims,
		func(t *gjwt.Token) (any, error) {
			kid, _ := t.Header["kid"].(string)
			return c.jwks.key(ctx, kid, t.Method.Alg())
		},
		opts...,
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrIDTokenInvalid, err)
	}

	// Predicate validation (multi-tenant or preset-supplied): the iss claim
	// must be approved by the effective validator.
	if validator != nil {
		iss, _ := claims["iss"].(string)
		if iss == "" || !validator(iss) {
			return nil, fmt.Errorf("%w: issuer %q rejected", ErrIDTokenInvalid, iss)
		}
	}

	// Bind the token to this login: the nonce must match the one we issued.
	got, _ := claims["nonce"].(string)
	if subtle.ConstantTimeCompare([]byte(got), []byte(nonce)) != 1 {
		return nil, fmt.Errorf("%w: nonce mismatch", ErrIDTokenInvalid)
	}

	// Audience must be exactly our client id. OIDC Core 3.1.3.7 tells the
	// client to reject a token whose audiences it does not trust, and permits
	// several audiences when "azp" names the authorized party. Nothing in this
	// library's configuration says the caller trusts a second audience, so a
	// multi-audience token is refused rather than accepted on the strength of
	// "azp" alone. An explicit allowlist can lift this later.
	aud := audienceClaim(claims)
	if len(aud) != 1 || aud[0] != c.cfg.ClientID {
		return nil, fmt.Errorf("%w: audience does not match client id", ErrIDTokenInvalid)
	}

	// OIDC Core §2 requires "iat" as a NumericDate; WithIssuedAt only validates
	// it when present, so enforce presence and numeric type explicitly.
	if _, ok := numericClaim(claims, "iat"); !ok {
		return nil, fmt.Errorf("%w: missing or non-numeric iat", ErrIDTokenInvalid)
	}

	out := &IDClaims{
		Subject:       stringClaim(claims, "sub"),
		Issuer:        stringClaim(claims, "iss"),
		Audience:      aud,
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

// numericClaim returns the value at key and reports whether it is a JSON number
// (float64 or json.Number). gjwt.MapClaims holds NumericDate claims as
// float64, but a token decoded via UseNumber arrives as json.Number; both count
// as numeric per RFC 7519.
func numericClaim(m gjwt.MapClaims, key string) (any, bool) {
	v, ok := m[key]
	if !ok {
		return nil, false
	}
	switch v.(type) {
	case float64, json.Number:
		return v, true
	}
	return nil, false
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
