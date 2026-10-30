// Package jwspayload checks the payload of a compact JWS for what the verifier cannot honour.
package jwspayload

import (
	"encoding/base64"
	"errors"
	"strings"

	"github.com/Glyndor/authcore/auth/oauth/internal/jsonstrict"
)

// ErrText reports a payload whose text is not what the signer wrote.
var ErrText = errors.New("jws payload carries text that is not valid UTF-8")

// readClaims are the claims the verifier and Claims read. A spelling of one of
// them that differs only in case is refused: a consumer that reads the claims
// without regard to case would take another identity from the same token. Any
// other claim keeps its own spelling.
var readClaims = []string{"iss", "sub", "aud", "exp", "nbf", "iat", "nonce", "azp", "tid", "email", "email_verified", "name"}

// CheckText refuses a compact JWS whose payload carries text that would be
// ambiguous or repaired when it is read: a byte that is not valid UTF-8 and a surrogate
// escape that stands in no pair both become U+FFFD, and the identity the
// payload names is read from that text.
//
// A payload that cannot be decoded is left to the parser, which reports it.
func CheckText(token string) error {
	_, rest, ok := strings.Cut(token, ".")
	if !ok {
		return nil
	}
	payload, _, ok := strings.Cut(rest, ".")
	if !ok {
		return nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return nil
	}
	if !jsonstrict.WellFormedText(raw) {
		return ErrText
	}
	return jsonstrict.UniqueMembers(raw, readClaims...)
}
