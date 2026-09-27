package oauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/Glyndor/authcore/internal/keymanager"
)

// appleSecretAudience is the "aud" claim Apple expects on the client secret
// JWT: literally the Apple ID domain. A secret signed for any other aud is
// refused by Apple's token endpoint.
// #nosec G101 -- this is Apple's public OIDC audience, not a credential.
const appleSecretAudience = "https://appleid.apple.com"

// appleKeySrc is the label handed to DecodePEMBlock so the refusal messages
// name the source of the bytes when an Apple .p8 fails to parse.
const appleKeySrc = "Apple .p8 key"

// validateAppleTenChar verifies a 10-character Apple identifier: exactly ten
// bytes, each in [A-Z0-9]. The byte form of a malformed input never appears
// in the message: the message names the field and the rule.
func validateAppleTenChar(s, field string) error {
	if len(s) != 10 {
		return fmt.Errorf("%w: %s must be 10 characters, got %d", ErrInvalidConfig, field, len(s))
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			return fmt.Errorf("%w: %s must contain only A-Z and 0-9", ErrInvalidConfig, field)
		}
	}
	return nil
}

// validateAppleClientID refuses an empty client id and one with surrounding
// whitespace. Exchange sends Config.ClientID verbatim as client_id, and the
// secret's "sub" must be the same string, so the two must not drift apart
// through trimming.
func validateAppleClientID(clientID string) error {
	if clientID == "" {
		return fmt.Errorf("%w: client ID must not be empty", ErrInvalidConfig)
	}
	if trimmed := strings.TrimSpace(clientID); trimmed != clientID {
		return fmt.Errorf("%w: client ID must not be empty or carry surrounding whitespace", ErrInvalidConfig)
	}
	return nil
}

// parseAppleP8 decodes one PKCS#8 PEM block of type "PRIVATE KEY" via the
// keymanager's strict parser (which forbids text before the BEGIN line,
// headers, and anything after the END line), then parses it as an EC private
// key and verifies the curve is P-256. Anything else is refused with a
// message that does not echo any byte of the input.
//
// The complete decode happens here, once, so the returned closure does no
// parsing on the hot path; the only allocation on signing is the JWT itself.
// p8 is not retained beyond the parsing step.
func parseAppleP8(p8 []byte) (*ecdsa.PrivateKey, error) {
	der, err := keymanager.DecodePEMBlock(p8, "PRIVATE KEY", appleKeySrc)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidConfig, err)
	}
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("%w: Apple .p8 key is not a valid PKCS#8 private key", ErrInvalidConfig)
	}
	ec, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%w: Apple .p8 key must be ECDSA (Apple client secrets use ES256)", ErrInvalidConfig)
	}
	if ec.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%w: Apple .p8 key must use the P-256 curve", ErrInvalidConfig)
	}
	return ec, nil
}
