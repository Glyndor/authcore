package jwt

import (
	"context"
	"time"
)

// defaultDenylistTimeout bounds the revocation lookup when VerifyAccessToken is
// called (the context-less convenience method). It keeps a slow or hung
// Denylist store from blocking the verifying goroutine indefinitely. Use
// VerifyAccessTokenContext to supply your own deadline instead.
const defaultDenylistTimeout = 5 * time.Second

// Denylist is the optional, opt-in hook that makes a stateless access token
// revocable before it expires.
//
// Access tokens are stateless JWTs: by default the only thing bounding an issued
// token is its expiry (AccessTokenTTL). That is enough for most applications.
// When you need instant revocation — logout-everywhere, a compromised account,
// an admin force-logout — set Config.Denylist to an implementation backed by
// your own store (in-memory, Redis, a database table) and VerifyAccessToken
// will reject any token whose session has been revoked.
//
// The denylist is keyed by the token's "jti", which equals the TokenPair
// SessionID and is stable across rotations — so revoking one entry kills the
// whole session, every access token in it, immediately.
//
// That holds while you refresh with RotateTokens, which carries the original
// jti forward. CreateTokens mints a fresh one on every call, so a deployment
// that refreshes by calling CreateTokens instead must store the newest
// SessionID and revoke that: access tokens issued under an earlier jti are not
// covered by the entry and remain valid until their own exp. See the "When not
// to rotate" section of docs/jwt.md.
//
// Leaving Config.Denylist nil keeps the stateless fast path: no lookup, no
// store, no per-request cost.
type Denylist interface {
	// IsRevoked reports whether the session identified by jti has been revoked.
	//
	// It is called only for an access token that has already passed signature,
	// expiry, audience and type checks, so it runs at most once per valid
	// request. Return (false, nil) when the session is active. A non-nil error
	// is surfaced to the caller wrapped, and must fail closed — the token is
	// not accepted — so a store outage cannot silently bypass revocation.
	//
	// Implementations must be safe for concurrent use and should be fast; honour
	// ctx for cancellation and deadlines.
	IsRevoked(ctx context.Context, jti string) (bool, error)
}
