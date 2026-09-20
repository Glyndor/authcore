package jwt

import "errors"

// Sentinel errors returned by the jwt package.
// Use errors.Is to check for these in calling code.
//
// # Error safety
//
// Map errors to HTTP responses as follows — never forward err.Error() directly
// to clients, as wrapped messages may contain internal implementation details:
//
//	claims, err := jwtMod.VerifyAccessToken(token)
//	if err != nil {
//	    log.Printf("token verification: %v", err) // log full detail
//	    switch {
//	    case errors.Is(err, jwt.ErrTokenExpired):
//	        c.JSON(401, map[string]string{"error": "token expired"})
//	    default:
//	        c.JSON(401, map[string]string{"error": "unauthorized"})
//	    }
//	    return
//	}
var (
	// ErrInvalidConfig is returned when jwt.Config fails validation.
	//
	// Safety: INTERNAL — programming or startup error, should never reach a handler.
	ErrInvalidConfig = errors.New("jwt: invalid configuration")

	// ErrTokenExpired is returned when a token's exp claim is in the past.
	//
	// Safety: CLIENT-SAFE — use to return a specific "token expired" message
	// so the client knows to refresh rather than re-authenticate.
	ErrTokenExpired = errors.New("jwt: token has expired")

	// ErrTokenInvalid is returned when the token signature does not verify,
	// or when an unsupported algorithm is present in the JOSE header.
	//
	// Safety: INTERNAL — the wrapped message may reveal the algorithm name.
	// Return a generic "unauthorized" to the client.
	ErrTokenInvalid = errors.New("jwt: token is invalid")

	// ErrTokenMalformed is returned when the token is not a properly formed
	// three-part dot-separated string, or when any part cannot be base64url-decoded.
	//
	// Safety: INTERNAL — return a generic "unauthorized" to the client.
	ErrTokenMalformed = errors.New("jwt: token is malformed")

	// ErrTokenOversized is returned when a token string exceeds the library's
	// length cap. The cap stops a caller from forcing base64+JSON work on a
	// multi-megabyte string before the signature is even checked, and stops
	// the same input at issuance so the issuer does not produce a token the
	// verifier will refuse.
	//
	// Safety: INTERNAL. The wrapped message names the limit and the actual
	// size for the operator; return a generic "unauthorized" to the client.
	ErrTokenOversized = errors.New("jwt: token exceeds maximum size")

	// ErrWrongTokenType is returned when an access token is passed to a
	// function that expects a refresh token, or vice-versa.
	//
	// Safety: INTERNAL — reveals the internal token type distinction.
	// Return a generic "unauthorized" to the client.
	ErrWrongTokenType = errors.New("jwt: wrong token type")

	// ErrInvalidSubject is returned when CreateTokens is called with a
	// subject that is not a valid UUID v7 (RFC 9562 §5.7, case-insensitive).
	//
	// Safety: INTERNAL — programming error in the caller. Treat as a 500.
	ErrInvalidSubject = errors.New("jwt: subject must be a valid UUID v7")

	// ErrTokenRevoked is returned by VerifyAccessToken when a configured
	// Denylist reports the token's session as revoked. The token's signature
	// and expiry were valid; it was explicitly killed.
	//
	// Safety: INTERNAL — return a generic "unauthorized" to the client, which
	// should re-authenticate.
	//
	// A Denylist store that returns its own error (transport, timeout, parse)
	// is wrapped with the store's error verbatim and surfaced through the
	// same Verify call. There is no sentinel for store failures; check for
	// ErrTokenRevoked to handle a clean revocation, and treat any other
	// error as an internal problem with the denylist itself.
	ErrTokenRevoked = errors.New("jwt: token has been revoked")

	// ErrNotInitialised is returned by HashRefreshToken on a zero-value
	// JWT[T] (a module that was never constructed by New). A zero-value
	// module carries no HMAC secret, so calling it would emit a hash
	// under an empty key, a fingerprint no caller asked for.
	// VerifyRefreshTokenHash returns false instead, since its result
	// type is bool.
	//
	// Safety: INTERNAL. The call site that owns the zero value is the one
	// to fix.
	ErrNotInitialised = errors.New("jwt: module not initialised")
)
