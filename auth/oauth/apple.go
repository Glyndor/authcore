package oauth

import (
	"context"

	"github.com/Glyndor/authcore/auth/oauth/internal/apple"
)

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
	return apple.ClientSecret(ErrInvalidConfig, teamID, keyID, clientID, p8)
}
