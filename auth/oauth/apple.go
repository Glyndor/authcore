package oauth

import (
	"context"
	"time"

	gjwt "github.com/golang-jwt/jwt/v5"
)

// appleSecretLifetime bounds how long an Apple client secret is good for. The
// value is short on purpose: an Apple client secret is a JWT, and a leaked
// secret is good for as long as it is valid. Five minutes is well under
// Apple's documented ceiling (15777000 s, ~6 months), and keeps the blast
// radius of a log disclosure or a heap dump to minutes.
const appleSecretLifetime = 5 * time.Minute

// nowFn is the clock used to stamp "iat" and "exp" on the client secret.
// Injected from a test variable so the acceptance pair of AppleClientSecret
// can pin "iat" against a known value without sleeping.
var nowFn = time.Now

// AppleClientSecret returns a Config.ClientSecretFunc that signs a fresh JWT
// on every call, suitable as the client secret at Apple's token endpoint.
//
// The arguments match the four fields Apple publishes in the Developer
// portal for a Services ID: teamID (10 chars, [A-Z0-9]), keyID (10 chars,
// [A-Z0-9]), clientID (the Services ID, treated as opaque but must be
// non-empty and free of surrounding whitespace), and p8 (the contents of the
// .p8 file Apple provided: a single PEM block of type "PRIVATE KEY" with no
// headers and nothing but whitespace around it).
//
// Each call signs a fresh ES256 JWT (header alg=ES256, kid=keyID), claims
// iss=teamID, iat=now, exp=now+appleSecretLifetime, aud=appleSecretAudience,
// sub=clientID. The lifetime is short because a leaked token is good for
// the remainder of its life; Apple's ceiling is 15777000 s (~6 months),
// which is far too long for a per-Exchange secret.
//
// The returned function honours ctx: it returns ctx.Err() without signing
// when ctx is already done. The error then wraps nothing secret (the key
// is never logged).
func AppleClientSecret(teamID, keyID, clientID string, p8 []byte) (func(context.Context) (string, error), error) {
	if err := validateAppleTenChar(teamID, "team ID"); err != nil {
		return nil, err
	}
	if err := validateAppleTenChar(keyID, "key ID"); err != nil {
		return nil, err
	}
	if err := validateAppleClientID(clientID); err != nil {
		return nil, err
	}

	key, err := parseAppleP8(p8)
	if err != nil {
		return nil, err
	}

	team := teamID
	kid := keyID
	sub := clientID
	sign := func(ctx context.Context) (string, error) {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		now := nowFn()
		tok := gjwt.NewWithClaims(gjwt.SigningMethodES256, gjwt.MapClaims{
			"iss": team,
			"iat": now.Unix(),
			"exp": now.Add(appleSecretLifetime).Unix(),
			"aud": appleSecretAudience,
			"sub": sub,
		})
		tok.Header["kid"] = kid
		// SignedString returns the underlying signing error verbatim. The
		// key itself never reaches a log line; the configured logger only
		// sees the wrapped error from Exchange.
		return tok.SignedString(key)
	}
	return sign, nil
}
