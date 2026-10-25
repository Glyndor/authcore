package jwttest

import (
	"context"
	"crypto/ed25519"
	"time"

	"github.com/Glyndor/authcore/auth/jwt/internal/claims"
	"github.com/Glyndor/authcore/auth/jwt/internal/denylist"
	"github.com/Glyndor/authcore/auth/jwt/internal/issue"
	"github.com/Glyndor/authcore/auth/jwt/internal/refreshhash"
	"github.com/Glyndor/authcore/auth/jwt/internal/rotation"
	"github.com/Glyndor/authcore/auth/jwt/internal/verify"
	"github.com/Glyndor/authcore/internal/keymanager"
)

// Config mirrors the fields of jwt.Config the sub-packages consume.
type Config struct {
	AccessTokenTTL     time.Duration
	RefreshTokenTTL    time.Duration
	Issuer             string
	Audience           []string
	ClockSkewLeeway    time.Duration
	Denylist           denylist.Revoker
	PreviousPublicKeys []ed25519.PublicKey
}

// DefaultConfig returns the same defaults jwt.DefaultConfig does.
func DefaultConfig() Config {
	return Config{
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 24 * time.Hour,
		Issuer:          "github.com/Glyndor/authcore",
		Audience:        []string{"github.com/Glyndor/authcore"},
	}
}

// Rig drives the issue, verify and rotation packages the way jwt.JWT does,
// but reads its clock from Now, a field a test assigns freely. Rig exists
// because the clock inside jwt.JWT is unexported and a sub-package's tests
// cannot reach it.
type Rig[T any] struct {
	Cfg  Config
	K    *Keys
	Now  time.Time
	Keys map[string]ed25519.PublicKey // accepted kid -> public key
}

// NewRig returns a Rig for cfg over keys k with its clock pinned to Epoch.
func NewRig[T any](k *Keys, cfg Config) *Rig[T] {
	r := &Rig[T]{Cfg: cfg, K: k, Now: Epoch}
	r.Keys = map[string]ed25519.PublicKey{k.KeyID(): k.Pub}
	for _, prev := range cfg.PreviousPublicKeys {
		r.Keys[keymanager.KeyID(prev)] = prev
	}
	return r
}

// IssueParams is the signing policy of this rig.
func (r *Rig[T]) IssueParams() issue.Params {
	return issue.Params{
		Priv:       r.K.Priv,
		KID:        r.K.KeyID(),
		Issuer:     r.Cfg.Issuer,
		Audience:   r.Cfg.Audience,
		AccessTTL:  r.Cfg.AccessTokenTTL,
		RefreshTTL: r.Cfg.RefreshTokenTTL,
		Secret:     r.K.Secret,
		Log:        SilentLogger{},
	}
}

// VerifyParams is the verification policy of this rig.
func (r *Rig[T]) VerifyParams() verify.Params {
	return verify.Params{
		Keys:     r.Keys,
		Issuer:   r.Cfg.Issuer,
		Audience: r.Cfg.Audience[0],
		Leeway:   r.Cfg.ClockSkewLeeway,
		Denylist: r.Cfg.Denylist,
	}
}

// CreateTokens starts a session for subject at r.Now.
func (r *Rig[T]) CreateTokens(subject string, extra T) (*issue.Result, error) {
	return issue.Create(r.IssueParams(), r.Now, subject, extra)
}

// VerifyAccessToken verifies an access token with the denylist bounded by its
// default deadline, as the jwt package does for its context-less method.
func (r *Rig[T]) VerifyAccessToken(token string) (*claims.Access[T], error) {
	ctx, cancel := denylist.Context(r.Cfg.Denylist)
	defer cancel()
	return r.VerifyAccessTokenContext(ctx, token)
}

// VerifyAccessTokenContext verifies an access token under ctx.
func (r *Rig[T]) VerifyAccessTokenContext(ctx context.Context, token string) (*claims.Access[T], error) {
	return verify.Access[T](ctx, r.VerifyParams(), r.Now, token)
}

// RotateTokens exchanges a refresh token for a new pair, with the denylist
// bounded by its default deadline.
func (r *Rig[T]) RotateTokens(refreshToken string, extra T) (*issue.Result, error) {
	ctx, cancel := denylist.Context(r.Cfg.Denylist)
	defer cancel()
	return r.RotateTokensContext(ctx, refreshToken, extra)
}

// RotateTokensContext exchanges a refresh token for a new pair under ctx.
func (r *Rig[T]) RotateTokensContext(ctx context.Context, refreshToken string, extra T) (*issue.Result, error) {
	return rotation.Rotate(ctx, r.VerifyParams(), r.IssueParams(), r.Now, refreshToken, extra)
}

// HashRefreshToken returns the stored-hash form of a refresh token.
func (r *Rig[T]) HashRefreshToken(token string) string {
	return refreshhash.Compute(token, r.K.Secret)
}

// VerifyRefreshTokenHash reports whether storedHash is the hash of token.
func (r *Rig[T]) VerifyRefreshTokenHash(token, storedHash string) bool {
	return refreshhash.Equal(token, storedHash, r.K.Secret)
}
