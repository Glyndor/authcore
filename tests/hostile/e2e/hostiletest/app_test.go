package hostiletest_test

import (
	"context"
	"errors"
	"testing"

	"github.com/Glyndor/authcore/auth/jwt"
	"github.com/Glyndor/authcore/tests/hostile/e2e/hostiletest"
)

var ctx0 = context.Background()

func newApp(t *testing.T) *hostiletest.App {
	t.Helper()
	return hostiletest.NewApp(t, hostiletest.NewEnv(t), jwt.Config{})
}

func TestApp_loginRefreshLogout(t *testing.T) {
	ctx := context.Background()
	app := newApp(t)
	pair, err := app.Login(hostiletest.Subject)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.Authenticate(ctx, pair.AccessToken); err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	next, err := app.Refresh(ctx, pair.RefreshToken)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if next.SessionID != pair.SessionID {
		t.Error("rotation changed the session id")
	}
	if err := app.Logout(next.RefreshToken, true); err != nil {
		t.Fatalf("logout: %v", err)
	}
	if _, err := app.Authenticate(ctx, next.AccessToken); !errors.Is(err, jwt.ErrTokenRevoked) {
		t.Errorf("access token after an instant logout = %v, want ErrTokenRevoked", err)
	}
	if app.Sessions.Len() != 0 {
		t.Error("logout left a session row")
	}
}

func TestApp_refreshOutcomes(t *testing.T) {
	ctx := context.Background()
	app := newApp(t)
	pair, _ := app.Login(hostiletest.Subject)
	next, err := app.Refresh(ctx, pair.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.Refresh(ctx, pair.RefreshToken); !errors.Is(err, hostiletest.ErrReuse) {
		t.Fatalf("replay of a rotated token = %v, want ErrReuse", err)
	}
	if _, err := app.Refresh(ctx, next.RefreshToken); !errors.Is(err, hostiletest.ErrUnknown) {
		t.Errorf("the current token after the family was revoked = %v, want ErrUnknown", err)
	}
	if _, err := app.Refresh(ctx, "not.a.token"); !errors.Is(err, hostiletest.ErrUnknown) {
		t.Errorf("garbage = %v, want ErrUnknown", err)
	}
	if err := app.Logout("not.a.token", false); !errors.Is(err, hostiletest.ErrUnknown) {
		t.Errorf("logout of garbage = %v, want ErrUnknown", err)
	}
}

func TestApp_refusesWhatTheModuleRefuses(t *testing.T) {
	ctx := context.Background()
	app := newApp(t)
	pair, _ := app.Login(hostiletest.Subject)
	// The access token hashes to a row only if it is the stored hash; make it
	// the stored hash so the module's own refusal is what decides.
	hash, _ := app.JWT.HashRefreshToken(pair.AccessToken)
	app.Sessions.Insert(hostiletest.Session{ID: "x", UserID: hostiletest.Subject, Hash: hash})
	if _, err := app.Refresh(ctx, pair.AccessToken); !errors.Is(err, jwt.ErrWrongTokenType) {
		t.Errorf("access token presented as refresh = %v, want ErrWrongTokenType", err)
	}
}

func TestApp_beforeSwapRunsOnceBetweenRotationAndTheUpdate(t *testing.T) {
	app := newApp(t)
	pair, _ := app.Login(hostiletest.Subject)
	calls := 0
	app.BeforeSwap = func() {
		calls++
		if _, ok := app.Sessions.ByHash(pair.RefreshTokenHash); !ok {
			t.Error("the row was already swapped when the hook ran")
		}
	}
	if _, err := app.Refresh(ctx0, pair.RefreshToken); err != nil || calls != 1 {
		t.Errorf("refresh = %v after %d hook calls, want nil after 1", err, calls)
	}
}

func TestApp_aSwapThatLostTheRaceDiscardsThePair(t *testing.T) {
	app := newApp(t)
	pair, _ := app.Login(hostiletest.Subject)
	if app.Sessions.Swap(pair.SessionID, "stale", "x") {
		t.Error("swap from a hash the row does not hold succeeded")
	}
	if app.Sessions.Swap("missing", pair.RefreshTokenHash, "x") {
		t.Error("swap on a missing row succeeded")
	}
	if !app.Sessions.Swap(pair.SessionID, pair.RefreshTokenHash, "x") {
		t.Error("swap from the stored hash failed")
	}
	if id, ok := app.Sessions.RetiredOwner(pair.RefreshTokenHash); !ok || id != pair.SessionID {
		t.Error("the retired hash was not remembered")
	}
	if _, ok := app.Sessions.RetiredOwner("never"); ok {
		t.Error("an unknown hash has a retired owner")
	}
}

func TestDenylist_failsWhenDownAndKeepsWhatWasAdded(t *testing.T) {
	d := hostiletest.NewDenylist()
	d.Add("a")
	if rev, err := d.IsRevoked(context.Background(), "a"); err != nil || !rev {
		t.Errorf("added id = %v, %v, want revoked", rev, err)
	}
	if rev, _ := d.IsRevoked(context.Background(), "b"); rev {
		t.Error("an id nobody added is revoked")
	}
	if d.Lookups() != 2 {
		t.Errorf("lookups = %d, want 2", d.Lookups())
	}
	d.SetDown(true)
	if _, err := d.IsRevoked(context.Background(), "a"); !errors.Is(err, hostiletest.ErrStoreDown) {
		t.Errorf("down store = %v, want ErrStoreDown", err)
	}
}
