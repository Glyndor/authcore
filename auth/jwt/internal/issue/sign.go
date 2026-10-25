package issue

import (
	"crypto/ed25519"
	"fmt"

	gjwt "github.com/golang-jwt/jwt/v5"
)

// SignToken encodes claims as a signed EdDSA JWT and returns the compact serialisation.
// kid is embedded in the JOSE header so verifiers can select the correct public key.
func SignToken(claims gjwt.Claims, key ed25519.PrivateKey, kid string) (string, error) {
	token := gjwt.NewWithClaims(gjwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = kid
	signed, err := token.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}
	return signed, nil
}
