// Package issue signs the access and refresh tokens of a session.
package issue

import (
	"crypto/ed25519"
	"fmt"
	"strings"
	"time"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/jwt/internal/claims"
	"github.com/Glyndor/authcore/auth/jwt/internal/jwterr"
	"github.com/Glyndor/authcore/auth/jwt/internal/refreshhash"
	"github.com/Glyndor/authcore/auth/jwt/internal/tokenid"
)

// Params is the signing policy a module applies to every pair it issues.
type Params struct {
	// Priv and KID are the current signing key and its JOSE "kid".
	Priv ed25519.PrivateKey
	KID  string
	// Issuer and Audience are written into the "iss" and "aud" claims.
	Issuer   string
	Audience []string
	// AccessTTL and RefreshTTL are the token lifetimes.
	AccessTTL, RefreshTTL time.Duration
	// Secret keys the HMAC that hashes refresh tokens.
	Secret []byte
	Log    authcore.Logger
}

// Result is the pair Tokens returns. Its fields mirror jwt.TokenPair one for
// one, so the jwt package converts it with a plain type conversion.
type Result struct {
	AccessToken           string
	AccessTokenExpiresAt  time.Time
	RefreshToken          string
	RefreshTokenExpiresAt time.Time
	RefreshTokenHash      string
	SessionID             string
}

// Create starts a new session for subject: it validates and lowercases the
// UUID v7 subject, mints a fresh jti and signs the pair under it.
func Create[T any](p Params, now time.Time, subject string, extra T) (*Result, error) {
	subject = strings.ToLower(subject)
	if !tokenid.IsUUIDv7(subject) {
		return nil, jwterr.ErrInvalidSubject
	}

	jti, err := tokenid.NewJTI(now)
	if err != nil {
		return nil, err
	}

	return Tokens(p, now, subject, jti, extra)
}

// Tokens signs a new access+refresh pair for subject using the provided jti.
// Create generates a fresh jti; rotation reuses the existing session jti
// so that SessionID remains stable for the lifetime of the session.
func Tokens[T any](p Params, now time.Time, subject, jti string, extra T) (*Result, error) {
	// golang-jwt truncates the exp claim to whole seconds. Apply the same
	// truncation here so AccessTokenExpiresAt reports exactly what the signed
	// claim says; a sub-second TTL must not round in the operator's view.
	accessExpiresAt := now.Add(p.AccessTTL).Truncate(time.Second)
	refreshExpiresAt := now.Add(p.RefreshTTL).Truncate(time.Second)

	// ----- Access token -----
	accessToken, err := SignToken(claims.NewAccess(p.Issuer, subject, jti, p.Audience, extra, now, p.AccessTTL), p.Priv, p.KID)
	if err != nil {
		return nil, fmt.Errorf("sign access token: %w", err)
	}
	if n := len(accessToken); n > claims.MaxTokenLen {
		// Enforce the same cap the verifier applies. A token that exceeds the
		// limit would verify as ErrTokenOversized, so refuse at issuance with
		// a message that names the limit and the actual length instead of
		// letting the operator discover it on the next request.
		return nil, fmt.Errorf("%w: length %d exceeds %d byte limit (issuer=%d, audience=%d)",
			jwterr.ErrTokenOversized, n, claims.MaxTokenLen, len(p.Issuer), sumLen(p.Audience))
	}

	// ----- Refresh token (no extra) -----
	// Each refresh token gets a fresh random rid here, next to signing, so
	// claims.NewRefresh stays a pure constructor.
	rid, err := tokenid.NewRID()
	if err != nil {
		return nil, err
	}
	refreshToken, err := SignToken(claims.NewRefresh(p.Issuer, subject, jti, rid, p.Audience, now, p.RefreshTTL), p.Priv, p.KID)
	if err != nil {
		return nil, fmt.Errorf("sign refresh token: %w", err)
	}
	if n := len(refreshToken); n > claims.MaxTokenLen {
		return nil, fmt.Errorf("%w: length %d exceeds %d byte limit (issuer=%d, audience=%d)",
			jwterr.ErrTokenOversized, n, claims.MaxTokenLen, len(p.Issuer), sumLen(p.Audience))
	}

	p.Log.Debug("jwt: token pair issued (sub=%s, jti=%s)", subject, jti)

	return &Result{
		AccessToken:           accessToken,
		AccessTokenExpiresAt:  accessExpiresAt,
		RefreshToken:          refreshToken,
		RefreshTokenExpiresAt: refreshExpiresAt,
		RefreshTokenHash:      refreshhash.Compute(refreshToken, p.Secret),
		SessionID:             jti,
	}, nil
}

// sumLen returns the sum of len(entry) across entries. Used to surface the
// total audience bytes in an ErrTokenOversized message.
func sumLen(entries []string) int {
	n := 0
	for _, e := range entries {
		n += len(e)
	}
	return n
}
