// Package parse checks the compact JWT strings the jwt package issues: their
// shape, signature and registered claims.
//
// Token format (RFC 7519 / RFC 8037 EdDSA):
//
//	BASE64URL(header) + "." + BASE64URL(payload) + "." + BASE64URL(signature)
//
// Header  : {"alg":"EdDSA","kid":"<key-id>","typ":"JWT"}
// Payload : JSON object with registered + private claims
// Signature: Ed25519 signature over the raw "header.payload" ASCII bytes
//
// Access token payload : iss, sub, iat, exp, jti, type, extra
// Refresh token payload: iss, sub, iat, exp, jti, type, rid  (no extra). Each refresh
// token carries a random rid, so two tokens of one session never compare equal,
// whatever the clock says.
package parse

import (
	"crypto/ed25519"
	"fmt"
	"time"

	gjwt "github.com/golang-jwt/jwt/v5"

	"github.com/Glyndor/authcore/auth/jwt/internal/claims"
	"github.com/Glyndor/authcore/auth/jwt/internal/jwterr"
	"github.com/Glyndor/authcore/auth/jwt/internal/parse/errmap"
	"github.com/Glyndor/authcore/auth/jwt/internal/parse/keyfunc"
	"github.com/Glyndor/authcore/auth/jwt/internal/tokenid"
)

// Access validates the compact JWT string and returns the decoded access claims.
// now is injected to allow deterministic testing via clock.Fixed.
// issuer and audience are the expected "iss" and "aud" values the token must
// carry. Enforcing both defends against cross-service key reuse, where a token
// signed by the same key but issued for a different service would otherwise be
// accepted here.
// leeway is added to the expiration window to tolerate small clock skew between servers.
func Access[T any](tokenStr string, keys map[string]ed25519.PublicKey, now time.Time, issuer, audience string, leeway time.Duration) (*claims.Access[T], error) {
	if err := checkTokenString(tokenStr); err != nil {
		return nil, err
	}
	if err := checkObjectKeys(tokenStr); err != nil {
		return nil, err
	}
	var c claims.Access[T]
	_, err := gjwt.ParseWithClaims(
		tokenStr, &c,
		keyfunc.EdDSA(keys), // enforce EdDSA alg + select pub by kid; rejects HS256/RS256 confusion attacks and unknown key IDs
		parserOptions(now, issuer, audience, leeway)...,
	)
	if err != nil {
		return nil, errmap.Map(err)
	}
	if err := checkDates(c.RegisteredClaims); err != nil {
		return nil, err
	}
	if !tokenid.IsUUIDv7(c.Subject) {
		return nil, fmt.Errorf("%w: sub claim is not a UUID v7", jwterr.ErrTokenInvalid)
	}
	if !tokenid.IsUUIDv7(c.ID) {
		return nil, fmt.Errorf("%w: jti claim is not a UUID v7", jwterr.ErrTokenInvalid)
	}
	return &c, nil
}

// Refresh validates the compact JWT string and returns the decoded refresh claims.
// issuer and audience are the expected "iss" and "aud" values the token must
// carry. Enforcing both defends against cross-service key reuse, where a token
// signed by the same key but issued for a different service would otherwise be
// accepted here.
// leeway is added to the expiration window to tolerate small clock skew between servers.
func Refresh(tokenStr string, keys map[string]ed25519.PublicKey, now time.Time, issuer, audience string, leeway time.Duration) (*claims.Refresh, error) {
	if err := checkTokenString(tokenStr); err != nil {
		return nil, err
	}
	if err := checkObjectKeys(tokenStr); err != nil {
		return nil, err
	}
	var c claims.Refresh
	_, err := gjwt.ParseWithClaims(
		tokenStr, &c,
		keyfunc.EdDSA(keys), // enforce EdDSA alg + select pub by kid; rejects HS256/RS256 confusion attacks and unknown key IDs
		parserOptions(now, issuer, audience, leeway)...,
	)
	if err != nil {
		return nil, errmap.Map(err)
	}
	if err := checkDates(c.RegisteredClaims); err != nil {
		return nil, err
	}
	if !tokenid.IsUUIDv7(c.Subject) {
		return nil, fmt.Errorf("%w: sub claim is not a UUID v7", jwterr.ErrTokenInvalid)
	}
	if !tokenid.IsUUIDv7(c.ID) {
		return nil, fmt.Errorf("%w: jti claim is not a UUID v7", jwterr.ErrTokenInvalid)
	}
	return &c, nil
}

// parserOptions is the one list of claim checks both verifiers apply, so the
// access and refresh paths cannot drift apart: the refresh-path audience check
// could be deleted with the suite green before the two shared it (2026-09-25).
func parserOptions(now time.Time, issuer, audience string, leeway time.Duration) []gjwt.ParserOption {
	return []gjwt.ParserOption{
		gjwt.WithTimeFunc(func() time.Time { return now }), // inject clock so tests can freeze time
		gjwt.WithExpirationRequired(),                      // reject tokens without an exp claim
		gjwt.WithIssuedAt(),                                // reject tokens with iat in the future
		gjwt.WithIssuer(issuer),                            // token must be issued by this service
		gjwt.WithAudience(audience),                        // token must contain this audience value
		gjwt.WithLeeway(leeway),                            // tolerate small clock drift between servers
		gjwt.WithStrictDecoding(),                          // one spelling per token: no stray padding bits
	}
}

// checkTokenString bounds a token before it is parsed and keeps it to the
// compact JWS alphabet. The base64url decoder skips "\r" and "\n" and, unless
// strict, ignores the unused bits of a segment's last character, so a second
// spelling of an issued token verified; a caller that blocklists or
// deduplicates tokens by string must not see two.
func checkTokenString(tokenStr string) error {
	if len(tokenStr) > claims.MaxTokenLen {
		return fmt.Errorf("%w: length %d exceeds %d", jwterr.ErrTokenOversized, len(tokenStr), claims.MaxTokenLen)
	}
	for i := 0; i < len(tokenStr); i++ {
		c := tokenStr[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_', c == '.':
		default:
			return fmt.Errorf("%w: byte %d is outside the base64url alphabet", jwterr.ErrTokenMalformed, i)
		}
	}
	return nil
}
