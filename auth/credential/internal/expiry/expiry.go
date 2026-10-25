// Package expiry decides whether a credential token is outside its lifetime
// window.
package expiry

import "time"

// FutureSkew is how far into the future an issuance timestamp may sit before
// the token is rejected: a clock that has run more than a minute ahead must
// not mint a token that looks future-dated to a verifier on the correct time.
const FutureSkew = time.Minute

// Expired reports whether a token issued elapsed ago is outside its window:
// more than ttl in the past, or more than FutureSkew in the future.
//
// Only the future side is guarded. A clock that runs backwards after
// issuance extends a token's effective life, because elapsed is once more
// inside the TTL window; the full TTL is the upper bound on how much
// backwards drift the verifier absorbs.
func Expired(elapsed, ttl time.Duration) bool {
	return elapsed > ttl || elapsed < -FutureSkew
}
