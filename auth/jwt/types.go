package jwt

import (
	"context"
	"time"
)

// TokenPair holds the result of a successful token creation or rotation.
// The library never stores tokens — the application is responsible for
// persisting the RefreshTokenHash and associating it with the user.
type TokenPair struct {
	// AccessToken is the short-lived JWT for authenticating API requests.
	// Include this in the Authorization: Bearer header.
	// Default lifetime: 15 minutes.
	AccessToken string

	// AccessTokenExpiresAt is when AccessToken expires.
	// Send this to the client so it can schedule a token refresh proactively.
	AccessTokenExpiresAt time.Time

	// RefreshToken is the long-lived JWT for obtaining new access tokens.
	// Store this on the client side in secure, httpOnly storage.
	// Default lifetime: 24 hours.
	RefreshToken string

	// RefreshTokenExpiresAt is when RefreshToken expires.
	// After this time the user must log in again.
	RefreshTokenExpiresAt time.Time

	// RefreshTokenHash is the HMAC-SHA256 hex-encoded digest of RefreshToken.
	//
	// Store ONLY this value in your database — never the raw RefreshToken.
	// When a client presents a refresh token, call HashRefreshToken to
	// compute its hash and look it up in your database before calling
	// RotateTokens.
	RefreshTokenHash string

	// SessionID is the UUID v7 shared by both the access and refresh tokens as their "jti" claim.
	// It uniquely identifies the session and is stable across rotations. Use it as the
	// primary key for your session store to associate metadata such as device, IP address,
	// or last-seen time, and as the lookup/revocation key for the session as a whole.
	//
	// Note: the jti identifies the session, not an individual access token. All access
	// tokens issued within one session (including across rotations) share this jti, so
	// you cannot single out one access token by it — revocation is per-session.
	SessionID string
}

// Claims represents the verified payload extracted from an access token.
// It is returned by VerifyAccessToken after successful signature and
// expiry validation.
//
// T is the application-specific type passed to jwt.New. It corresponds to
// the "extra" field in the token payload.
type Claims[T any] struct {
	// Subject is the "sub" claim — the unique user identifier supplied
	// when CreateTokens was called.
	Subject string

	// Issuer is the "iss" claim as configured in jwt.Config.Issuer.
	Issuer string

	// Audience is the "aud" claim — the intended recipients of the token,
	// as configured in jwt.Config.Audience.
	Audience []string

	// TokenID is the "jti" claim — the session identifier. It equals the
	// TokenPair.SessionID returned at creation and is shared by the refresh
	// token and every rotation, so it names the session, not this single token.
	TokenID string

	// IssuedAt is when the token was created (the "iat" claim).
	IssuedAt time.Time

	// ExpiresAt is when the token expires (the "exp" claim).
	ExpiresAt time.Time

	// Extra holds the application-specific claims embedded in the token.
	// These are the values passed to CreateTokens or RotateTokens.
	Extra T
}

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
// to rotate" section of docs/modules/jwt.md.
//
// Leaving Config.Denylist nil keeps the stateless fast path: no lookup, no
// store, no per-request cost.
type Denylist interface {
	// IsRevoked reports whether the session identified by jti has been revoked.
	//
	// It is called only for a token that has already passed signature,
	// expiry, audience and type checks: an access token in VerifyAccessToken,
	// a refresh token in RotateTokens. It runs at most once per valid request. Return (false, nil) when the session is active. A non-nil error
	// is surfaced to the caller wrapped, and must fail closed — the token is
	// not accepted — so a store outage cannot silently bypass revocation.
	//
	// Implementations must be safe for concurrent use and should be fast; honour
	// ctx for cancellation and deadlines.
	IsRevoked(ctx context.Context, jti string) (bool, error)
}
