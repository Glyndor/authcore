// Package errmap translates golang-jwt parse failures into the module's public
// token sentinels.
package errmap

import (
	"errors"
	"fmt"

	gjwt "github.com/golang-jwt/jwt/v5"

	"github.com/Glyndor/authcore/auth/jwt/internal/jwterr"
)

// Map converts golang-jwt sentinel errors to our public sentinels.
// This decouples callers from the underlying library's error types, so we can
// swap or upgrade the JWT library without breaking the public API.
//
// When the underlying parser joins several failures into one error (for example
// a token that is both expired and carries the wrong issuer), the non-expiry
// failure takes precedence: a caller that treats ErrTokenExpired as "refresh
// and retry" would otherwise loop on a token whose iss is wrong, because the
// retry would carry the same wrong iss. ErrTokenExpired is therefore reserved
// for the case where expiry is the only failure.
func Map(err error) error {
	for _, sentinel := range nonExpirySentinels {
		if errors.Is(err, sentinel) {
			return jwterr.ErrTokenInvalid
		}
	}
	switch {
	case errors.Is(err, gjwt.ErrTokenExpired):
		return jwterr.ErrTokenExpired
	case errors.Is(err, gjwt.ErrTokenMalformed):
		return jwterr.ErrTokenMalformed
	default:
		return fmt.Errorf("%w: %w", jwterr.ErrTokenInvalid, err)
	}
}

// nonExpirySentinels is the set of golang-jwt sentinel errors that indicate a
// claim or signature mismatch other than exp. Membership in this list raises
// the mapped error to ErrTokenInvalid even when the same input also expired,
// so a refresh-and-retry caller does not loop on a token that is wrong for a
// reason other than its lifetime.
//
// ErrTokenInvalidClaims is deliberately omitted: golang-jwt wraps every
// validation failure (including expiry) under it, so its presence does not
// distinguish a claim mismatch from an exp failure.
var nonExpirySentinels = []error{
	gjwt.ErrTokenSignatureInvalid,
	gjwt.ErrTokenUnverifiable,
	gjwt.ErrTokenInvalidIssuer,
	gjwt.ErrTokenInvalidAudience,
	gjwt.ErrTokenInvalidSubject,
	gjwt.ErrTokenInvalidId,
	gjwt.ErrTokenRequiredClaimMissing,
	gjwt.ErrTokenNotValidYet,
	gjwt.ErrTokenUsedBeforeIssued,
}
