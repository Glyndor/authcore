// Package rotation exchanges a valid refresh token for a new token pair that
// keeps the session identifier.
package rotation

import (
	"context"
	"time"

	"github.com/Glyndor/authcore/auth/jwt/internal/issue"
	"github.com/Glyndor/authcore/auth/jwt/internal/verify"
)

// Rotate verifies refreshToken under vp and, when it is valid and its session
// is not revoked, issues a new pair for the same subject and jti under ip.
func Rotate[T any](ctx context.Context, vp verify.Params, ip issue.Params, now time.Time, refreshToken string, extra T) (*issue.Result, error) {
	c, err := verify.Refresh(ctx, vp, now, refreshToken)
	if err != nil {
		return nil, err
	}

	ip.Log.Debug("jwt: rotating token (sub=%s, jti=%s)", c.Subject, c.ID)

	return issue.Tokens(ip, now, c.Subject, c.ID, extra)
}
