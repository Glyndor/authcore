// Package candidate describes one usable signing key of a JWKS and selects the
// one that may verify a given token, enforcing the JWK's alg/use/key_ops
// restrictions.
package candidate

import (
	"crypto"
	"fmt"

	"github.com/Glyndor/authcore/auth/oauth/internal/safetext"
)

// Candidate is a parsed JWK paired with the metadata needed to enforce the
// per-key alg/use/key_ops restrictions at selection time. Two candidates may
// share a kid (RFC 7517 permits an RSA key and an EC key under one kid) and
// the verifier picks by token alg.
type Candidate struct {
	// Pub is the parsed public key.
	Pub crypto.PublicKey
	// Alg, Use and KeyOps are the JWK "alg", "use" and "key_ops" members,
	// empty when the key does not declare them.
	Alg    string
	Use    string
	KeyOps map[string]struct{}
	// Issuer is the JWK "issuer" member, "" when the key carries none.
	Issuer string
}

// Pick walks candidates and returns the first one whose declared
// alg/use/key_ops match the token's alg. kid is carried only so the error
// message names the right value; the matching itself depends on alg. A
// failure wraps errFetch.
func Pick(errFetch error, candidates []Candidate, kid, alg string) (Candidate, error) {
	for _, cand := range candidates {
		if !cand.Matches(alg) {
			continue
		}
		return cand, nil
	}
	if kid == "" {
		return Candidate{}, fmt.Errorf("%w: no candidate matches alg %s", errFetch, safetext.Quote(alg))
	}
	return Candidate{}, fmt.Errorf("%w: no candidate for kid %s matches alg %s", errFetch, safetext.Quote(kid), safetext.Quote(alg))
}

// Matches reports whether the Candidate may verify a token signed with alg,
// applying the JWK's declared alg/use/key_ops restrictions. A key published
// with alg:"RS256" cannot verify PS256 (RFC 8725 §3.1); a key with
// key_ops:["encrypt"] cannot verify signatures at all (RFC 7517 §4.3).
func (cand Candidate) Matches(alg string) bool {
	if cand.Alg != "" && cand.Alg != alg {
		return false
	}
	if cand.Use != "" && cand.Use != "sig" {
		return false
	}
	if len(cand.KeyOps) > 0 {
		if _, ok := cand.KeyOps["verify"]; !ok {
			return false
		}
	}
	return true
}
