// Package denylist applies the optional revocation hook that makes a stateless
// access token revocable before it expires.
package denylist

import (
	"context"
	"fmt"
	"time"

	"github.com/Glyndor/authcore/auth/jwt/internal/jwterr"
)

// DefaultTimeout bounds the revocation lookup when VerifyAccessToken is
// called (the context-less convenience method). It keeps a slow or hung
// Denylist store from blocking the verifying goroutine indefinitely. Use
// VerifyAccessTokenContext to supply your own deadline instead.
const DefaultTimeout = 5 * time.Second

// Revoker is the lookup the jwt.Denylist interface declares. Any jwt.Denylist
// satisfies it.
type Revoker interface {
	IsRevoked(ctx context.Context, jti string) (bool, error)
}

// Context returns the context a context-less call runs the lookup under: a
// background context bounded by DefaultTimeout when r is set, a plain
// background context when it is nil.
func Context(r Revoker) (context.Context, context.CancelFunc) {
	if r == nil {
		return context.Background(), func() {}
	}
	return context.WithTimeout(context.Background(), DefaultTimeout)
}

// Check asks r whether the session jti is revoked. A nil r never revokes.
// A store failure is wrapped and returned verbatim; there is no sentinel for it.
func Check(ctx context.Context, r Revoker, jti string) error {
	if r == nil {
		return nil
	}
	revoked, err := r.IsRevoked(ctx, jti)
	if err != nil {
		return fmt.Errorf("jwt: denylist lookup: %w", err)
	}
	// A store that ignores its context can answer "not revoked" after the
	// deadline already passed. That answer was not given in time, so it cannot
	// vouch for the token: fail closed rather than accept on a late "no".
	if !revoked && ctx.Err() != nil {
		return fmt.Errorf("jwt: denylist lookup: %w", ctx.Err())
	}
	if revoked {
		return jwterr.ErrTokenRevoked
	}
	return nil
}
