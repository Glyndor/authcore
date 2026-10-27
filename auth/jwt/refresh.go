package jwt

import (
	"github.com/Glyndor/authcore/auth/jwt/internal/refreshhash"
)

// HashRefreshToken returns the HMAC-SHA256 hex digest of the given token
// string using the library's managed refresh secret.
//
// Use this to derive the database lookup key before calling RotateTokens:
//
//	hash, err := jwtMod.HashRefreshToken(clientToken)
//	if err != nil { return serverError() }
//	row, err := db.FindByHash(hash)
//	if err != nil { return http.StatusUnauthorized }
//	newPair, err := jwtMod.RotateTokens(clientToken, freshClaims)
//
// HashRefreshToken returns ErrNotInitialised on a zero-value or nil JWT[T].
// The signature changed from `string` to `(string, error)` so a module
// that was never constructed by New cannot emit a hash under an empty
// HMAC secret.
func (j *JWT[T]) HashRefreshToken(token string) (string, error) {
	if j == nil || !j.initialised {
		return "", ErrNotInitialised
	}
	return refreshhash.Compute(token, j.secret), nil
}

// VerifyRefreshTokenHash reports whether token produces the same HMAC-SHA256
// digest as storedHash using a constant-time comparison to prevent timing attacks.
//
// Call this instead of a plain string equality check when validating a client's
// refresh token against the hash stored in your database:
//
//	if !jwtMod.VerifyRefreshTokenHash(clientToken, row.RefreshTokenHash) {
//	    return http.StatusUnauthorized
//	}
//	newPair, err := jwtMod.RotateTokens(clientToken, freshClaims)
//
// VerifyRefreshTokenHash returns false on a zero-value or nil JWT[T]: a module
// with no HMAC secret cannot verify anything, and answering true would
// let a caller mistake "no key was used" for "the key matched".
func (j *JWT[T]) VerifyRefreshTokenHash(token, storedHash string) bool {
	if j == nil || !j.initialised {
		return false
	}
	return refreshhash.Equal(token, storedHash, j.secret)
}
