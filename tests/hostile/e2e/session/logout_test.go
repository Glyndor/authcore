package session

import (
	"errors"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/jwt"
	"github.com/Glyndor/authcore/tests/hostile/e2e/hostiletest"
)

// Logout without a denylist, the default of docs/guides/secure-login.md §6:
// the session cannot be renewed, but the access token the client holds works
// until its exp. Then the clock passes exp and it does not.
func TestE2E_Logout_plainLogoutStopsRenewalAndNotTheAccessToken(t *testing.T) {
	app, e := newApp(t, jwt.Config{AccessTokenTTL: 10 * time.Minute, RefreshTokenTTL: time.Hour})
	pair, _ := app.Login(hostiletest.Subject)
	if err := app.Logout(pair.RefreshToken, false); err != nil {
		t.Fatal(err)
	}
	if _, err := app.Refresh(ctx, pair.RefreshToken); !errors.Is(err, hostiletest.ErrUnknown) {
		t.Errorf("refresh after logout = %v, want ErrUnknown", err)
	}
	if _, err := app.Authenticate(ctx, pair.AccessToken); err != nil {
		t.Errorf("access token after a plain logout = %v, want valid until exp (documented)", err)
	}
	if _, err := app.Authenticate(ctx, hostiletest.Age(t, e, pair.AccessToken, 9*time.Minute)); err != nil {
		t.Errorf("access token 9 minutes into a 10 minute life = %v, want valid", err)
	}
	if _, err := app.Authenticate(ctx, hostiletest.Age(t, e, pair.AccessToken, 10*time.Minute)); !errors.Is(err, jwt.ErrTokenExpired) {
		t.Errorf("access token at exp = %v, want ErrTokenExpired", err)
	}
	// The library alone does not know about the logout: a thief with the
	// refresh token can still mint tokens from it; the stored hash is what
	// stops the application from honouring that.
	if _, err := app.JWT.RotateTokens(pair.RefreshToken, hostiletest.Extra{}); err != nil {
		t.Errorf("library rotation after a plain logout = %v, want accepted (stateless)", err)
	}
}

// Instant kill: the session id on the denylist ends the access token, the
// rotation, and every later token of that session, whichever side holds them.
func TestE2E_Logout_instantLogoutKillsEveryTokenOfTheSession(t *testing.T) {
	app, _ := newApp(t, jwt.Config{})
	pair, _ := app.Login(hostiletest.Subject)
	next, err := app.Refresh(ctx, pair.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	if err := app.Logout(next.RefreshToken, true); err != nil {
		t.Fatal(err)
	}
	for name, tok := range map[string]string{"pre-rotation": pair.AccessToken, "post-rotation": next.AccessToken} {
		if _, err := app.Authenticate(ctx, tok); !errors.Is(err, jwt.ErrTokenRevoked) {
			t.Errorf("%s access token = %v, want ErrTokenRevoked", name, err)
		}
	}
	for name, tok := range map[string]string{"pre-rotation": pair.RefreshToken, "post-rotation": next.RefreshToken} {
		if _, err := app.JWT.RotateTokens(tok, hostiletest.Extra{}); !errors.Is(err, jwt.ErrTokenRevoked) {
			t.Errorf("%s refresh token through the library = %v, want ErrTokenRevoked", name, err)
		}
	}
}

// Revoking one session does not touch the sessions next to it, including the
// same user's other device.
func TestE2E_Logout_revocationIsPerSession(t *testing.T) {
	app, _ := newApp(t, jwt.Config{})
	phone, _ := app.Login(hostiletest.Subject)
	laptop, _ := app.Login(hostiletest.Subject)
	if phone.SessionID == laptop.SessionID {
		t.Fatal("two logins share a session id")
	}
	if err := app.Logout(phone.RefreshToken, true); err != nil {
		t.Fatal(err)
	}
	if _, err := app.Authenticate(ctx, laptop.AccessToken); err != nil {
		t.Errorf("laptop access token = %v, want valid", err)
	}
	if _, err := app.Refresh(ctx, laptop.RefreshToken); err != nil {
		t.Errorf("laptop refresh = %v, want accepted", err)
	}
}

// A store that cannot answer must not be read as "not revoked": verification
// and rotation both fail closed, and nothing is issued.
func TestE2E_Logout_aDownDenylistFailsClosed(t *testing.T) {
	app, _ := newApp(t, jwt.Config{})
	pair, _ := app.Login(hostiletest.Subject)
	app.Deny.SetDown(true)
	if _, err := app.Authenticate(ctx, pair.AccessToken); !errors.Is(err, hostiletest.ErrStoreDown) {
		t.Errorf("verify with the store down = %v, want the store error", err)
	}
	if _, err := app.Refresh(ctx, pair.RefreshToken); !errors.Is(err, hostiletest.ErrStoreDown) {
		t.Errorf("refresh with the store down = %v, want the store error", err)
	}
	if row, ok := app.Sessions.ByHash(pair.RefreshTokenHash); !ok || row.Hash != pair.RefreshTokenHash {
		t.Error("a refused rotation changed the stored hash")
	}
	app.Deny.SetDown(false)
	if _, err := app.Refresh(ctx, pair.RefreshToken); err != nil {
		t.Errorf("refresh once the store is back = %v, want accepted", err)
	}
}

// Garbage never reaches the denylist: the lookup runs only for tokens that
// passed signature and expiry.
func TestE2E_Logout_untrustedTokensDoNotCostALookup(t *testing.T) {
	app, e := newApp(t, jwt.Config{AccessTokenTTL: time.Minute, RefreshTokenTTL: time.Hour})
	pair, _ := app.Login(hostiletest.Subject)
	foreign := hostiletest.Age(t, hostiletest.NewEnv(t), pair.AccessToken, 0)
	expired := hostiletest.Age(t, e, pair.AccessToken, time.Minute)
	for name, tok := range map[string]string{"garbage": "x.y.z", "empty": "", "foreign key": foreign, "expired": expired} {
		if _, err := app.Authenticate(ctx, tok); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if got := app.Deny.Lookups(); got != 0 {
		t.Errorf("denylist consulted %d times for untrusted tokens, want 0", got)
	}
}

// The non-rotating alternative of docs/modules/jwt.md ("When not to rotate"):
// CreateTokens on every refresh starts a new jti, so a denylist entry for the
// newest session id does not cover the access token issued under the earlier
// one. That is the promise the documentation says is weaker, pinned.
func TestE2E_Logout_withoutRotationADenylistEntryCoversOnlyTheNewestSegment(t *testing.T) {
	app, _ := newApp(t, jwt.Config{})
	first, _ := app.Login(hostiletest.Subject)
	second, err := app.JWT.CreateTokens(hostiletest.Subject, hostiletest.Extra{})
	if err != nil {
		t.Fatal(err)
	}
	if first.SessionID == second.SessionID {
		t.Fatal("CreateTokens reused a session id")
	}
	app.Deny.Add(second.SessionID)
	if _, err := app.Authenticate(ctx, second.AccessToken); !errors.Is(err, jwt.ErrTokenRevoked) {
		t.Errorf("newest segment = %v, want ErrTokenRevoked", err)
	}
	if _, err := app.Authenticate(ctx, first.AccessToken); err != nil {
		t.Errorf("earlier segment = %v, want valid until its own exp (documented)", err)
	}
}
