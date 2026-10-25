// Package verify decides whether a token is acceptable to the module: it
// parses it, checks that it is the kind of token the caller asked for, and
// asks the denylist whether its session was revoked.
package verify

import (
	"context"
	"crypto/ed25519"
	"time"

	"github.com/Glyndor/authcore/auth/jwt/internal/claims"
	"github.com/Glyndor/authcore/auth/jwt/internal/denylist"
	"github.com/Glyndor/authcore/auth/jwt/internal/jwterr"
	"github.com/Glyndor/authcore/auth/jwt/internal/parse"
)

// Params is the verification policy a module applies to every token.
type Params struct {
	// Keys maps each accepted "kid" to its public key.
	Keys map[string]ed25519.PublicKey
	// Issuer and Audience are the "iss" and "aud" values a token must carry.
	Issuer, Audience string
	// Leeway tolerates small clock skew between servers.
	Leeway time.Duration
	// Denylist is optional; nil means tokens are never checked for revocation.
	Denylist denylist.Revoker
}

// Access parses and validates an access token, then asks the denylist (if
// any) whether its session was revoked.
//
// Revocation is checked last — only an otherwise-valid access token is worth
// a denylist lookup, so a garbage or expired token never reaches the store.
func Access[T any](ctx context.Context, p Params, now time.Time, token string) (*claims.Access[T], error) {
	c, err := parse.Access[T](token, p.Keys, now, p.Issuer, p.Audience, p.Leeway)
	if err != nil {
		return nil, err
	}
	if c.Type != claims.TypeAccess {
		return nil, jwterr.ErrWrongTokenType
	}
	if err := denylist.Check(ctx, p.Denylist, c.ID); err != nil {
		return nil, err
	}
	return c, nil
}

// Refresh parses and validates a refresh token, then asks the denylist (if
// any) whether its session was revoked.
func Refresh(ctx context.Context, p Params, now time.Time, token string) (*claims.Refresh, error) {
	c, err := parse.Refresh(token, p.Keys, now, p.Issuer, p.Audience, p.Leeway)
	if err != nil {
		return nil, err
	}
	if c.Type != claims.TypeRefresh {
		return nil, jwterr.ErrWrongTokenType
	}
	if err := denylist.Check(ctx, p.Denylist, c.ID); err != nil {
		return nil, err
	}
	return c, nil
}
