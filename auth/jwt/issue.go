package jwt

import (
	"github.com/Glyndor/authcore/auth/jwt/internal/issue"
)

// CreateTokens generates a new access and refresh token pair for subject.
//
// subject is the UUID v7 that identifies the user in your system. It is stored
// in the "sub" JWT claim and returned in Claims.Subject after verification.
// Only UUID v7 is accepted (RFC 9562 §5.7); any casing is allowed — the value
// is normalised to lowercase before signing.
//
// extra holds the application-specific claims embedded in the access token
// under the "extra" key. Use struct{}{} if no custom claims are needed.
// The refresh token never carries extra claims.
//
// The returned TokenPair contains:
//
//	pair.AccessToken           — include in Authorization: Bearer on API requests
//	pair.AccessTokenExpiresAt  — send to the client to schedule proactive renewal
//	pair.RefreshToken          — store in a secure, httpOnly client-side location
//	pair.RefreshTokenExpiresAt: when this refresh token expires; each rotation issues a new one, so a session has no absolute end unless you store its start
//	pair.RefreshTokenHash      — store in your database; never store the raw token
//	pair.SessionID             — UUID v7 jti shared by both tokens; primary key for session store
//
// The same jti is carried by the access token, the refresh token, and every
// rotation of the session, so claims.TokenID after VerifyAccessToken equals
// pair.SessionID. It identifies the session, not an individual access token —
// access tokens within one session are not distinguishable by jti.
//
// The library does not persist any of these values.
func (j *JWT[T]) CreateTokens(subject string, extra T) (*TokenPair, error) {
	if j == nil || !j.initialised {
		return nil, ErrNotInitialised
	}
	r, err := issue.Create(j.issueParams(), j.clock.Now(), subject, extra)
	if err != nil {
		return nil, err
	}
	return (*TokenPair)(r), nil
}

// issueParams snapshots the signing policy the issue package applies.
func (j *JWT[T]) issueParams() issue.Params {
	return issue.Params{
		Priv:       j.priv,
		KID:        j.kid,
		Issuer:     j.cfg.Issuer,
		Audience:   j.cfg.Audience,
		AccessTTL:  j.cfg.AccessTokenTTL,
		RefreshTTL: j.cfg.RefreshTokenTTL,
		Secret:     j.secret,
		Log:        j.log,
	}
}
