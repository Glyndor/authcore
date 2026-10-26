// Package session attacks the whole login, refresh, logout and stolen-refresh
// story the way docs/guides/secure-login.md and docs/modules/jwt.md tell an
// application to build it: a real jwt module, an in-memory sessions table with
// the conditional UPDATE, and a denylist. The adversary holds every token the
// client ever held.
package session

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/jwt"
	"github.com/Glyndor/authcore/tests/hostile/e2e/hostiletest"
)

var ctx = context.Background()

func newApp(t *testing.T, cfg jwt.Config) (*hostiletest.App, *hostiletest.Env) {
	t.Helper()
	e := hostiletest.NewEnv(t)
	return hostiletest.NewApp(t, e, cfg), e
}

// The happy path, and what a rotation keeps and changes: the session id and
// subject stay, the refresh token and the stored hash change.
func TestE2E_Session_loginAndRotationKeepTheSessionAndChangeTheTokens(t *testing.T) {
	app, _ := newApp(t, jwt.Config{})
	pair, err := app.Login(hostiletest.Subject)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := app.Authenticate(ctx, pair.AccessToken)
	if err != nil || claims.Subject != hostiletest.Subject || claims.TokenID != pair.SessionID {
		t.Fatalf("authenticate = %+v, %v", claims, err)
	}
	next, err := app.Refresh(ctx, pair.RefreshToken)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if next.SessionID != pair.SessionID {
		t.Errorf("session id changed across rotation: %s -> %s", pair.SessionID, next.SessionID)
	}
	// The access token carries no random part, so inside one second a rotation
	// may reissue identical bytes; only the refresh token is guaranteed to change.
	if next.RefreshToken == pair.RefreshToken || next.RefreshTokenHash == pair.RefreshTokenHash {
		t.Error("rotation returned a refresh token it had already issued")
	}
	row, ok := app.Sessions.ByHash(next.RefreshTokenHash)
	if !ok || row.ID != pair.SessionID || row.UserID != hostiletest.Subject {
		t.Errorf("stored row after rotation = %+v, %v", row, ok)
	}
	if _, ok := app.Sessions.ByHash(pair.RefreshTokenHash); ok {
		t.Error("the replaced hash still finds a live row")
	}
}

// What rotation does NOT invalidate, stated by docs/modules/jwt.md: the access
// token the client already holds keeps working until its own exp, and the
// library alone still accepts the replaced refresh token, because it holds no
// state. Both are the application's half, and the next test shows it closing
// the second one.
func TestE2E_Session_rotationInvalidatesNothingInTheLibrary(t *testing.T) {
	app, _ := newApp(t, jwt.Config{})
	pair, _ := app.Login(hostiletest.Subject)
	if _, err := app.Refresh(ctx, pair.RefreshToken); err != nil {
		t.Fatal(err)
	}
	if _, err := app.Authenticate(ctx, pair.AccessToken); err != nil {
		t.Errorf("access token issued before the rotation = %v, want still valid until exp", err)
	}
	if _, err := app.JWT.RotateTokens(pair.RefreshToken, hostiletest.Extra{}); err != nil {
		t.Errorf("library rotation of the replaced refresh token = %v, want accepted (stateless)", err)
	}
}

// Reuse detection, the application's decision: a refresh token presented after
// its rotation finds no live row, finds the retired one, and revokes the whole
// family. From then on nothing of that session works, new tokens included.
func TestE2E_Session_reuseOfARotatedRefreshTokenKillsTheFamily(t *testing.T) {
	app, _ := newApp(t, jwt.Config{})
	pair, _ := app.Login(hostiletest.Subject)
	next, err := app.Refresh(ctx, pair.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := app.Refresh(ctx, pair.RefreshToken); !errors.Is(err, hostiletest.ErrReuse) {
		t.Fatalf("thief replays the old token = %v, want ErrReuse", err)
	}
	if _, err := app.Refresh(ctx, next.RefreshToken); !errors.Is(err, hostiletest.ErrUnknown) {
		t.Errorf("legitimate client afterwards = %v, want ErrUnknown (family revoked)", err)
	}
	for name, access := range map[string]string{"old access": pair.AccessToken, "new access": next.AccessToken} {
		if _, err := app.Authenticate(ctx, access); !errors.Is(err, jwt.ErrTokenRevoked) {
			t.Errorf("%s token after the family was revoked = %v, want ErrTokenRevoked", name, err)
		}
	}
	if _, err := app.JWT.RotateTokens(next.RefreshToken, hostiletest.Extra{}); !errors.Is(err, jwt.ErrTokenRevoked) {
		t.Errorf("library rotation after revocation = %v, want ErrTokenRevoked", err)
	}
	if app.Sessions.Len() != 0 {
		t.Error("revoked family left a session row")
	}
}

// A chain of rotations: every token but the last is replaced, the thief can
// choose any of them, and each choice is reuse.
func TestE2E_Session_everyEarlierLinkOfTheChainIsReuse(t *testing.T) {
	for victim := 0; victim < 4; victim++ {
		app, _ := newApp(t, jwt.Config{})
		pair, _ := app.Login(hostiletest.Subject)
		chain := []string{pair.RefreshToken}
		for i := 0; i < 4; i++ {
			next, err := app.Refresh(ctx, chain[len(chain)-1])
			if err != nil {
				t.Fatalf("rotation %d: %v", i, err)
			}
			chain = append(chain, next.RefreshToken)
		}
		if _, err := app.Refresh(ctx, chain[victim]); !errors.Is(err, hostiletest.ErrReuse) {
			t.Errorf("replay of link %d of 5 = %v, want ErrReuse", victim, err)
		}
	}
}

// Two users, one table: a refresh token never touches the other user's row, and
// reuse by one user's thief leaves the other user's session alone.
func TestE2E_Session_sessionsOfTwoUsersDoNotCross(t *testing.T) {
	app, _ := newApp(t, jwt.Config{})
	a, _ := app.Login(hostiletest.Subject)
	b, _ := app.Login(hostiletest.Other)
	nextA, err := app.Refresh(ctx, a.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.Refresh(ctx, a.RefreshToken); !errors.Is(err, hostiletest.ErrReuse) {
		t.Fatalf("replay on A = %v", err)
	}
	if _, err := app.Refresh(ctx, b.RefreshToken); err != nil {
		t.Errorf("B after A's family was revoked = %v, want a normal refresh", err)
	}
	if _, err := app.Authenticate(ctx, b.AccessToken); err != nil {
		t.Errorf("B's access token = %v, want valid", err)
	}
	if _, err := app.Authenticate(ctx, nextA.AccessToken); !errors.Is(err, jwt.ErrTokenRevoked) {
		t.Errorf("A's access token = %v, want ErrTokenRevoked", err)
	}
	claims, _ := app.Authenticate(ctx, b.AccessToken)
	if claims.Subject != hostiletest.Other {
		t.Errorf("B's token carries subject %s", claims.Subject)
	}
}

// The wire type is part of the contract: a refresh token is no access token and
// the reverse, even when the application's own table is made to hold the hash.
func TestE2E_Session_tokenTypesDoNotSubstitute(t *testing.T) {
	app, _ := newApp(t, jwt.Config{})
	pair, _ := app.Login(hostiletest.Subject)
	if _, err := app.Authenticate(ctx, pair.RefreshToken); !errors.Is(err, jwt.ErrWrongTokenType) {
		t.Errorf("refresh token as access = %v, want ErrWrongTokenType", err)
	}
	if _, err := app.JWT.RotateTokens(pair.AccessToken, hostiletest.Extra{}); !errors.Is(err, jwt.ErrWrongTokenType) {
		t.Errorf("access token as refresh = %v, want ErrWrongTokenType", err)
	}
	if got := app.Deny.Lookups(); got != 0 {
		t.Errorf("a wrong-type token reached the denylist %d times, want 0", got)
	}
}

// The window of one second: expiry is measured in whole seconds, so a token's
// life is exactly its TTL in claims, and aged by exactly that TTL it is gone,
// never "still good for the rest of the second".
func TestE2E_Session_aTokenLivesExactlyItsTTL(t *testing.T) {
	app, e := newApp(t, jwt.Config{AccessTokenTTL: time.Second, RefreshTokenTTL: time.Minute})
	pair, _ := app.Login(hostiletest.Subject)
	claims, err := app.JWT.VerifyAccessToken(pair.AccessToken)
	if err == nil {
		if got := claims.ExpiresAt.Sub(claims.IssuedAt); got != time.Second {
			t.Errorf("access lifetime in claims = %s, want 1s", got)
		}
	} else if !errors.Is(err, jwt.ErrTokenExpired) {
		t.Fatalf("verify: %v", err) // the second may turn over before the check; nothing else may fail
	}
	for _, age := range []time.Duration{time.Second, 2 * time.Second, time.Hour} {
		if _, err := app.JWT.VerifyAccessToken(hostiletest.Age(t, e, pair.AccessToken, age)); !errors.Is(err, jwt.ErrTokenExpired) {
			t.Errorf("1s token aged %s = %v, want ErrTokenExpired", age, err)
		}
	}
	rt := hostiletest.Age(t, e, pair.RefreshToken, time.Minute-5*time.Second)
	if _, err := app.JWT.RotateTokens(rt, hostiletest.Extra{}); err != nil {
		t.Errorf("refresh token 5s before its TTL = %v, want accepted", err)
	}
	if _, err := app.JWT.RotateTokens(hostiletest.Age(t, e, pair.RefreshToken, time.Minute), hostiletest.Extra{}); !errors.Is(err, jwt.ErrTokenExpired) {
		t.Errorf("refresh token at its TTL = %v, want ErrTokenExpired", err)
	}
}

// The stored hash is compared whole: a row whose hash was cut, altered at the
// tail, re-cased or padded does not pass for the token it was made from, and
// neither does the right hash for another token.
func TestE2E_Session_theStoredHashIsComparedWhole(t *testing.T) {
	app, _ := newApp(t, jwt.Config{})
	pair, _ := app.Login(hostiletest.Subject)
	other, _ := app.Login(hostiletest.Other)
	h := pair.RefreshTokenHash
	if !app.JWT.VerifyRefreshTokenHash(pair.RefreshToken, h) {
		t.Fatal("the genuine pair does not verify")
	}
	altered := h[:len(h)-1] + "g" // 'g' is not a hex digit, so the tail always differs
	for name, stored := range map[string]string{
		"empty": "", "first half": h[:len(h)/2], "first 8": h[:8], "tail altered": altered,
		"upper case": strings.ToUpper(h), "padded": h + "0", "leading space": " " + h,
		"another session's hash": other.RefreshTokenHash,
	} {
		if app.JWT.VerifyRefreshTokenHash(pair.RefreshToken, stored) {
			t.Errorf("stored hash %q verified the token", name)
		}
	}
	if app.JWT.VerifyRefreshTokenHash(other.RefreshToken, h) {
		t.Error("another session's token verified against this hash")
	}
}
