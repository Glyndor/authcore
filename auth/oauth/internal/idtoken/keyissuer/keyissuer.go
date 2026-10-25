// Package keyissuer enforces the JWK "issuer" member of the key that signed an
// ID token against the token's own claims.
package keyissuer

import (
	"fmt"
	"strings"

	gjwt "github.com/golang-jwt/jwt/v5"

	"github.com/Glyndor/authcore/auth/oauth/internal/safetext"
)

// Check enforces the JWK "issuer" member of the key that signed the
// token. An empty keyIssuer means the key is not restricted. A keyIssuer
// holding the "{tenantid}" template is completed with the token's "tid"
// claim, which must then be present; the result must equal the token's "iss"
// exactly.
func Check(invalid error, keyIssuer string, claims gjwt.MapClaims) error {
	if keyIssuer == "" {
		return nil
	}
	want := keyIssuer
	if strings.Contains(keyIssuer, "{tenantid}") {
		tid, _ := claims["tid"].(string)
		if tid == "" {
			return fmt.Errorf("%w: the signing key is restricted to %s and the token has no tid", invalid, safetext.Quote(keyIssuer))
		}
		want = strings.ReplaceAll(keyIssuer, "{tenantid}", tid)
	}
	if iss, _ := claims["iss"].(string); iss != want {
		return fmt.Errorf("%w: issuer %s is not the %s the signing key is restricted to", invalid, safetext.Quote(iss), safetext.Quote(want))
	}
	return nil
}
