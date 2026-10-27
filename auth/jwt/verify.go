package jwt

import (
	"context"
	"time"

	"github.com/Glyndor/authcore/auth/jwt/internal/claims"
	"github.com/Glyndor/authcore/auth/jwt/internal/denylist"
	"github.com/Glyndor/authcore/auth/jwt/internal/verify"
)

// VerifyAccessToken parses and validates an access token string.
//
// On success it returns the verified Claims extracted from the token payload,
// including the application-specific Extra fields.
// On failure it returns one of the following sentinel errors:
//
//	jwt.ErrTokenExpired   — exp claim is in the past
//	jwt.ErrTokenInvalid   — signature invalid, unsupported algorithm,
//	                        or iss/aud claim does not match Config
//	jwt.ErrTokenMalformed — not a valid three-part JWT string
//	jwt.ErrWrongTokenType — token is a refresh token, not an access token
//	jwt.ErrTokenRevoked   — a configured Denylist reports the token's session revoked
//
// If a configured Denylist returns its own error (transport, timeout, parse),
// the error is wrapped with the store's error verbatim and returned through
// this call. There is no sentinel for store failures; treat any error that
// is not ErrTokenRevoked as an internal problem with the denylist itself.
//
// Use errors.Is for error inspection:
//
//	claims, err := jwtMod.VerifyAccessToken(token)
//	if errors.Is(err, jwt.ErrTokenExpired) { ... }
//
// When a Denylist is configured (Config.Denylist), the revocation lookup runs
// under a background context bounded by a default 5-second timeout so a slow or
// hung store cannot block the verifying goroutine forever. Use
// VerifyAccessTokenContext to pass your own context (recommended for a
// network-backed denylist, e.g. to inherit the request deadline).
func (j *JWT[T]) VerifyAccessToken(token string) (*Claims[T], error) {
	if j == nil || !j.initialised {
		return nil, ErrNotInitialised
	}
	ctx, cancel := denylist.Context(j.denylist)
	defer cancel()
	return j.VerifyAccessTokenContext(ctx, token)
}

// VerifyAccessTokenContext is VerifyAccessToken with an explicit context that
// is passed to the configured Denylist (if any). The context bounds only the
// revocation lookup; signature and expiry checks are local and never block.
func (j *JWT[T]) VerifyAccessTokenContext(ctx context.Context, token string) (*Claims[T], error) {
	if j == nil || !j.initialised {
		return nil, ErrNotInitialised
	}
	c, err := verify.Access[T](ctx, j.verifyParams(), j.clock.Now(), token)
	if err != nil {
		return nil, err
	}
	return accessClaimsToClaims(c), nil
}

// verifyParams snapshots the verification policy the verify package applies.
func (j *JWT[T]) verifyParams() verify.Params {
	return verify.Params{
		Keys:     j.verifyKeys,
		Issuer:   j.cfg.Issuer,
		Audience: j.primaryAudience,
		Leeway:   j.cfg.ClockSkewLeeway,
		Denylist: j.denylist,
	}
}

// accessClaimsToClaims converts internal claims.Access to the public Claims type.
func accessClaimsToClaims[T any](c *claims.Access[T]) *Claims[T] {
	// gjwt.NumericDate pointers can be nil if the claim is absent in the token.
	// Extract them defensively to avoid nil pointer dereferences.
	var iat, exp time.Time
	if c.IssuedAt != nil {
		iat = c.IssuedAt.Time
	}
	if c.ExpiresAt != nil {
		exp = c.ExpiresAt.Time
	}
	return &Claims[T]{
		Subject:   c.Subject,
		Issuer:    c.Issuer,
		Audience:  []string(c.Audience),
		TokenID:   c.ID,
		IssuedAt:  iat.UTC(), // normalise to UTC regardless of the server's local timezone
		ExpiresAt: exp.UTC(),
		Extra:     c.Extra,
	}
}
