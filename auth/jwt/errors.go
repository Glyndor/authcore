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
)
