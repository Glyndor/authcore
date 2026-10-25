// Package jwsheader checks the protected header of a compact JWS for what the verifier cannot honour.
package jwsheader

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

// ErrCritical reports a header that carries the "crit" parameter.
var ErrCritical = errors.New("jws header lists critical extensions this verifier does not understand")

// RejectCritical refuses a compact JWS whose protected header has a "crit"
// member. RFC 7515 section 4.1.11 makes a token invalid when it lists a
// critical extension the recipient does not understand, and an ID token
// verifier understands none, so any "crit" (an empty or malformed one
// included) is grounds to refuse. A header that cannot be decoded is left to
// the signature parser, which reports it.
func RejectCritical(token string) error {
	head, _, ok := strings.Cut(token, ".")
	if !ok {
		return nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(head)
	if err != nil {
		return nil
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil {
		return nil
	}
	if _, present := members["crit"]; present {
		return ErrCritical
	}
	return nil
}
