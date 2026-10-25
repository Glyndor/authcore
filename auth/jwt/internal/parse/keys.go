package parse

import (
	"encoding/base64"
	"strings"

	"github.com/Glyndor/authcore/auth/jwt/internal/strictjson"
)

// The names this module reads from a token. A header or payload that spells one
// of them with other capitalisation, or repeats a key, is refused.
var (
	headerNames  = []string{"alg", "kid", "typ"}
	payloadNames = []string{"iss", "sub", "aud", "exp", "nbf", "iat", "jti", "type", "rid", "extra"}
)

// checkObjectKeys refuses a token whose header or payload holds a key that more
// than one JSON reader could take differently (see strictjson.Check). It runs
// on the bytes before any signature work and leaves a token that is not three
// base64url segments of JSON objects to the parser, which reports it.
func checkObjectKeys(tokenStr string) error {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil
	}
	for i, names := range [][]string{headerNames, payloadNames} {
		raw, err := base64.RawURLEncoding.Strict().DecodeString(parts[i])
		if err != nil {
			return nil
		}
		if err := strictjson.Check(raw, names...); err != nil {
			return err
		}
	}
	return nil
}
