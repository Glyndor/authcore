package hostiletest

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/Glyndor/authcore/auth/jwt"
)

// Outcomes of App.Refresh that are not a new pair.
var (
	// ErrUnknown: no live session holds the presented token.
	ErrUnknown = errors.New("no session holds this refresh token")
	// ErrReuse: the token was rotated away before. The session family is
	// revoked, which is the decision docs/guides/secure-login.md leaves to the
	// application.
	ErrReuse = errors.New("refresh token reused after rotation")
	// ErrRaced: another request rotated first; the new pair is discarded.
	ErrRaced = errors.New("rotated by another request first")
)

// App is the login flow of docs/guides/secure-login.md and docs/modules/jwt.md
// wired over the in-memory tables: the part the library tells the application
// to write, written to the letter of the documentation.
type App struct {
	JWT      *jwt.JWT[Extra]
	Sessions *Sessions
	Deny     *Denylist

	// BeforeSwap, when set, runs in Refresh after the module rotated and before
	// the conditional UPDATE. A test uses it to hold every request at that point
	// so they all reach the UPDATE having read the same stored hash.
	BeforeSwap func()
}

// NewApp builds an App whose jwt module consults a fresh Denylist.
func NewApp(t testing.TB, e *Env, cfg jwt.Config) *App {
	t.Helper()
	deny := NewDenylist()
	cfg.Denylist = deny
	return &App{JWT: e.JWT(t, cfg), Sessions: NewSessions(), Deny: deny}
}

// Login issues a pair for userID and stores the session row.
func (a *App) Login(userID string) (*jwt.TokenPair, error) {
	pair, err := a.JWT.CreateTokens(userID, Extra{Role: "user"})
	if err != nil {
		return nil, err
	}
	a.Sessions.Insert(Session{ID: pair.SessionID, UserID: userID, Hash: pair.RefreshTokenHash})
	return pair, nil
}

// Authenticate verifies an access token the way a protected route does.
func (a *App) Authenticate(ctx context.Context, access string) (*jwt.Claims[Extra], error) {
	return a.JWT.VerifyAccessTokenContext(ctx, access)
}

// Refresh is steps 1 to 5 of the rotation recipe, with reuse detection: a hash
// that no live row holds but a retired one did revokes that whole session.
func (a *App) Refresh(ctx context.Context, token string) (*jwt.TokenPair, error) {
	hash, err := a.JWT.HashRefreshToken(token)
	if err != nil {
		return nil, err
	}
	row, ok := a.Sessions.ByHash(hash)
	if !ok {
		if sid, was := a.Sessions.RetiredOwner(hash); was {
			a.Revoke(sid)
			return nil, ErrReuse
		}
		return nil, ErrUnknown
	}
	if !a.JWT.VerifyRefreshTokenHash(token, row.Hash) {
		return nil, ErrUnknown
	}
	pair, err := a.JWT.RotateTokensContext(ctx, token, Extra{Role: "user"})
	if err != nil {
		return nil, fmt.Errorf("rotate: %w", err)
	}
	if a.BeforeSwap != nil {
		a.BeforeSwap()
	}
	if !a.Sessions.Swap(row.ID, row.Hash, pair.RefreshTokenHash) {
		return nil, ErrRaced
	}
	return pair, nil
}

// Logout deletes the session of a refresh token. With instant it also adds the
// session id to the denylist, the "need instant kill" branch of the guide.
func (a *App) Logout(token string, instant bool) error {
	hash, err := a.JWT.HashRefreshToken(token)
	if err != nil {
		return err
	}
	row, ok := a.Sessions.ByHash(hash)
	if !ok {
		return ErrUnknown
	}
	if instant {
		a.Deny.Add(row.ID)
	}
	a.Sessions.Delete(row.ID)
	return nil
}

// Revoke kills a session family: row deleted and id denylisted.
func (a *App) Revoke(sessionID string) {
	a.Sessions.Delete(sessionID)
	a.Deny.Add(sessionID)
}
