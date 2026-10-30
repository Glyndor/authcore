// Package keyfunc supplies the golang-jwt key function that pins EdDSA and
// selects the verification key by the token's kid.
package keyfunc

import (
	"crypto/ed25519"
	"fmt"

	gjwt "github.com/golang-jwt/jwt/v5"

	"github.com/Glyndor/authcore/auth/jwt/internal/jwterr"
)

// EdDSA returns a gjwt.Keyfunc that enforces EdDSA and selects the
// verification key by the token's "kid" header from keys.
//
// Holding more than one key lets a verifier accept tokens signed by a previous
// key while issuing under the current one — the overlap that makes key rotation
// zero-downtime. A token whose kid is not in the set is rejected, so the
// verifier only ever trusts keys the operator has authorised.
func EdDSA(keys map[string]ed25519.PublicKey) gjwt.Keyfunc {
	return func(t *gjwt.Token) (any, error) {
		// Explicitly reject any algorithm that is not EdDSA.
		// Without this check an attacker could craft a token with alg=HS256
		// and sign it using the public key as the HMAC secret — a well-known
		// algorithm confusion attack that allows signature forgery.
		if _, ok := t.Method.(*gjwt.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("%w: unexpected alg %q", jwterr.ErrTokenInvalid, t.Header["alg"])
		}
		// Reject crit even when empty or null: no critical extension is supported.
		if _, ok := t.Header["crit"]; ok {
			return nil, fmt.Errorf("%w: unsupported crit header", jwterr.ErrTokenInvalid)
		}
		// Select the public key by the token's kid. An unknown (or missing) kid
		// is refused — the verifier never falls back to "try every key".
		kid, _ := t.Header["kid"].(string)
		pub, ok := keys[kid]
		if !ok {
			return nil, fmt.Errorf("%w: unrecognised kid %q", jwterr.ErrTokenInvalid, kid)
		}
		return pub, nil
	}
}
