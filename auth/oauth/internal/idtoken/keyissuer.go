package idtoken

import (
	"fmt"
	"strings"

	gjwt "github.com/golang-jwt/jwt/v5"
)

// checkKeyIssuer enforces the JWK "issuer" member of the key that signed the
// token. An empty keyIssuer means the key is not restricted. A keyIssuer
// holding the "{tenantid}" template is completed with the token's "tid"
// claim, which must then be present; the result must equal the token's "iss"
// exactly.
func checkKeyIssuer(invalid error, keyIssuer string, claims gjwt.MapClaims) error {
	if keyIssuer == "" {
		return nil
	}
	want := keyIssuer
	if strings.Contains(keyIssuer, "{tenantid}") {
		tid, _ := claims["tid"].(string)
		if tid == "" {
			return fmt.Errorf("%w: the signing key is restricted to %q and the token has no tid", invalid, keyIssuer)
		}
		want = strings.ReplaceAll(keyIssuer, "{tenantid}", tid)
	}
	if iss, _ := claims["iss"].(string); iss != want {
		return fmt.Errorf("%w: issuer %q is not the %q the signing key is restricted to", invalid, iss, want)
	}
	return nil
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
