package jwt

import (
	"context"

	"github.com/Glyndor/authcore/auth/jwt/internal/denylist"
	"github.com/Glyndor/authcore/auth/jwt/internal/rotation"
)

// RotateTokens verifies refreshToken, then generates and returns a new
// token pair for the same subject with fresh extra claims.
//
// Because the refresh token does not carry application-specific data, the
// caller must supply updated extra claims (typically re-fetched from the
// database at rotation time).
//
// Each refresh token carries a random rid, so two tokens of one session never
// compare equal, whatever the clock says.
//
// The SessionID (jti) is preserved across rotations — only the token strings
// and their expiry times change. This means the caller's session record
// primary key remains stable for the entire session lifetime.
//
// After a successful rotation, the old refresh token MUST be considered
// invalid. The application must replace the stored hash atomically:
//
//	db.ReplaceRefreshHash(oldHash, newPair.RefreshTokenHash)
//
// This function validates the token's signature and expiry but does NOT check
// whether the hash exists in a database — that is the application's responsibility
// and must happen before calling RotateTokens.
//
// Returns the same verification errors as VerifyAccessToken (a refresh token
// goes through the same signature / expiry / iss / aud pipeline), including
// ErrTokenRevoked: when a Denylist is configured, a revoked session cannot be
// rotated. Before 2026-09-25 it could, and the rotated access token verified
// again as soon as the denylist entry lapsed. The lookup runs under the same
// default 5-second timeout as VerifyAccessToken; use RotateTokensContext to
// pass your own context. It can also fail during signing, for example if the JSON encoder refuses
// a NaN or Inf in extra (rotating JWT[float64] with math.NaN() returns
// "sign access token: json: unsupported value: NaN"); verifyAccessToken
// cannot fail this way because it never serialises extra.
func (j *JWT[T]) RotateTokens(refreshToken string, extra T) (*TokenPair, error) {
	if j == nil || !j.initialised {
		return nil, ErrNotInitialised
	}
	ctx, cancel := denylist.Context(j.denylist)
	defer cancel()
	return j.RotateTokensContext(ctx, refreshToken, extra)
}

// RotateTokensContext is RotateTokens with an explicit context that is passed
// to the configured Denylist (if any). The context bounds only the revocation
// lookup.
func (j *JWT[T]) RotateTokensContext(ctx context.Context, refreshToken string, extra T) (*TokenPair, error) {
	if j == nil || !j.initialised {
		return nil, ErrNotInitialised
	}
	r, err := rotation.Rotate(ctx, j.verifyParams(), j.issueParams(), j.clock.Now(), refreshToken, extra)
	if err != nil {
		return nil, err
	}
	return (*TokenPair)(r), nil
}
