// Package idtoken validates an OpenID Connect ID token: signature against the provider keys, issuer,
// audience, azp, expiry, iat and nonce.
package idtoken

import (
	"context"
	"crypto/subtle"
	"fmt"
	"strings"

	gjwt "github.com/golang-jwt/jwt/v5"

	"github.com/Glyndor/authcore/auth/oauth/internal/idtoken/claimread"
	"github.com/Glyndor/authcore/auth/oauth/internal/idtoken/jwsheader"
	"github.com/Glyndor/authcore/auth/oauth/internal/idtoken/jwspayload"
	"github.com/Glyndor/authcore/auth/oauth/internal/idtoken/keyissuer"
	"github.com/Glyndor/authcore/auth/oauth/internal/jwks"
	"github.com/Glyndor/authcore/auth/oauth/internal/safetext"
)

// Algs are the asymmetric signing algorithms an ID token may use. HMAC
// and "none" are intentionally absent: accepting them would enable an
// algorithm-confusion or unsigned-token forgery.
var Algs = []string{
	"RS256", "RS384", "RS512",
	"PS256", "PS384", "PS512",
	"ES256", "ES384", "ES512",
}

// maxIDTokenLen caps an ID token before parsing. Real ID tokens are a few KiB
// (larger than an access token because of profile claims and an RSA signature);
// 16 KiB is generous while refusing a multi-megabyte string that would force
// base64+JSON work before the signature is checked.
const maxIDTokenLen = 16 * 1024

// KeySource selects the signing key for a token's kid and alg headers.
type KeySource interface {
	CandidateFor(ctx context.Context, kid, alg string) (jwks.Candidate, error)
}

// Params is what Verify needs from the client configuration.
type Params struct {
	// ClientID is the only audience, and the only azp, a token may carry.
	ClientID string
	// Issuer is the exact "iss" value; it is ignored when Validator is set.
	Issuer string
	// Validator approves the issuer by predicate when non-nil.
	Validator func(issuer string) bool
	// Keys supplies the signing keys.
	Keys KeySource
	// Invalid is the sentinel every failure is wrapped with (ErrIDTokenInvalid).
	Invalid error
}

// Claims holds the validated claims of an ID token.
type Claims struct {
	Subject       string
	Issuer        string
	Audience      []string
	Email         string
	EmailVerified bool
	Name          string
	Raw           map[string]any
}

// Verify validates idToken against p and returns its claims. See
// oauth.Client.VerifyIDToken for the checks it enforces; every failure wraps
// p.Invalid.
func Verify(ctx context.Context, p Params, idToken, nonce string) (*Claims, error) {
	if nonce == "" {
		return nil, fmt.Errorf("%w: no nonce supplied to verify against", p.Invalid)
	}
	if len(idToken) > maxIDTokenLen {
		return nil, fmt.Errorf("%w: token too large", p.Invalid)
	}
	// One token, one spelling. The base64url decoder skips "\n" and "\r" and,
	// unless strict, ignores the unused bits of a segment's last character,
	// so a second spelling of the same signed token verified. A caller that
	// deduplicates or blocklists tokens by string must not see two.
	if i := strings.IndexFunc(idToken, notCompactJWS); i >= 0 {
		return nil, fmt.Errorf("%w: byte %d is outside the base64url alphabet", p.Invalid, i)
	}

	if err := jwsheader.RejectCritical(idToken); err != nil {
		return nil, fmt.Errorf("%w: %w", p.Invalid, err)
	}

	// The subject the token names is read from the payload's text, so the
	// payload must carry the text the signer wrote: a byte or an escape the
	// decoder cannot read would be repaired, and the repaired value would
	// name another identity.
	if err := jwspayload.CheckText(idToken); err != nil {
		return nil, fmt.Errorf("%w: %w", p.Invalid, err)
	}

	opts := []gjwt.ParserOption{
		gjwt.WithStrictDecoding(),
		gjwt.WithValidMethods(Algs),
		gjwt.WithAudience(p.ClientID),
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
	validator := p.Validator
	if validator == nil {
		if p.Issuer == "" {
			return nil, fmt.Errorf("%w: no issuer configured", p.Invalid)
		}
		opts = append(opts, gjwt.WithIssuer(p.Issuer))
	}

	var claims gjwt.MapClaims
	var signer jwks.Candidate
	var keyErr error
	_, err := gjwt.ParseWithClaims(idToken, &claims,
		func(t *gjwt.Token) (any, error) {
			signer, keyErr = candidateFor(ctx, p.Keys, t)
			if keyErr != nil {
				return nil, keyErr
			}
			return signer.Pub, nil
		},
		opts...,
	)
	if err != nil {
		return nil, parseError(p.Invalid, err, keyErr)
	}

	// Predicate validation (multi-tenant or preset-supplied): the iss claim
	// must be approved by the effective validator.
	if validator != nil {
		iss, _ := claims["iss"].(string)
		if iss == "" || !validator(iss) {
			return nil, fmt.Errorf("%w: issuer %s rejected", p.Invalid, safetext.Quote(iss))
		}
	}

	// A key that names an issuer signs only that issuer's tokens. Microsoft
	// pins some keys of its common JWKS to one tenant and gives the rest the
	// "{tenantid}" template, and multi-tenant clients must check the token's
	// iss against it. Without this, a key scoped to the consumer tenant
	// verified a token claiming any other tenant under AzureMultiTenantIssuer
	// (measured 2026-09-25).
	if err := keyissuer.Check(p.Invalid, signer.Issuer, claims); err != nil {
		return nil, err
	}

	aud, err := checkBinding(p, claims, nonce)
	if err != nil {
		return nil, err
	}

	out := &Claims{
		Subject:       claimread.String(claims, "sub"),
		Issuer:        claimread.String(claims, "iss"),
		Audience:      aud,
		Email:         claimread.String(claims, "email"),
		EmailVerified: claimread.Bool(claims, "email_verified"),
		Name:          claimread.String(claims, "name"),
		Raw:           claims,
	}
	if out.Subject == "" {
		return nil, fmt.Errorf("%w: missing subject", p.Invalid)
	}
	return out, nil
}

func candidateFor(ctx context.Context, keys KeySource, token *gjwt.Token) (jwks.Candidate, error) {
	rawKid, present := token.Header["kid"]
	kid, textual := rawKid.(string)
	if present && !textual {
		return jwks.Candidate{}, fmt.Errorf("kid must be a string")
	}
	return keys.CandidateFor(ctx, kid, token.Method.Alg())
}

// parseError preserves key-selection causes, while parser causes can quote
// remote claims and belong only as bounded printable text in the diagnostic.
func parseError(invalid, diagnostic, keyErr error) error {
	if keyErr != nil {
		return fmt.Errorf("%w: %w", invalid, keyErr)
	}
	return fmt.Errorf("%w: %s", invalid, safetext.Clip(diagnostic.Error(), safetext.DefaultMax))
}

// checkBinding binds the token to this login and to this client: nonce,
// audience, azp and iat. It returns the audience list on success.
func checkBinding(p Params, claims gjwt.MapClaims, nonce string) ([]string, error) {
	// Bind the token to this login: the nonce must match the one we issued.
	got, _ := claims["nonce"].(string)
	if subtle.ConstantTimeCompare([]byte(got), []byte(nonce)) != 1 {
		return nil, fmt.Errorf("%w: nonce mismatch", p.Invalid)
	}

	// Audience must be exactly our client id. OIDC Core 3.1.3.7 tells the
	// client to reject a token whose audiences it does not trust, and permits
	// several audiences when "azp" names the authorized party. Nothing in this
	// library's configuration says the caller trusts a second audience, so a
	// multi-audience token is refused rather than accepted on the strength of
	// "azp" alone. An explicit allowlist can lift this later.
	aud := claimread.Audience(claims)
	if len(aud) != 1 || aud[0] != p.ClientID {
		return nil, fmt.Errorf("%w: audience does not match client id", p.Invalid)
	}
	// OIDC Core 3.1.3.7: when "azp" is present it must be our client id. A
	// token the provider issued at another client's request can still name us
	// as its only audience. #426 dropped this check along with the
	// multi-audience rule, and nothing noticed until 2026-09-25.
	if azp, ok := claims["azp"]; ok {
		if s, _ := azp.(string); s != p.ClientID {
			return nil, fmt.Errorf("%w: azp does not match client id", p.Invalid)
		}
	}

	// OIDC Core §2 requires "iat" as a NumericDate; WithIssuedAt only validates
	// it when present, so enforce presence and numeric type explicitly.
	if _, ok := claimread.Numeric(claims, "iat"); !ok {
		return nil, fmt.Errorf("%w: missing or non-numeric iat", p.Invalid)
	}
	return aud, nil
}

// notCompactJWS reports whether r can appear in a compact JWS: the base64url
// alphabet and the "." separating its three segments.
func notCompactJWS(r rune) bool {
	switch {
	case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		return false
	case r == '-', r == '_', r == '.':
		return false
	}
	return true
}
