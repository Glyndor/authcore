package session

import (
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/jwt"
	"github.com/Glyndor/authcore/tests/hostile/e2e/hostiletest"
)

// The client and a thief present the same refresh token at once, and so do 62
// more requests. Every one passes the hash compare; only the UPDATE that still
// sees the old hash wins, and nobody else is handed a pair.
func TestE2E_Race_manyRequestsWithOneRefreshTokenYieldOneWinner(t *testing.T) {
	app, _ := newApp(t, jwt.Config{})
	pair, _ := app.Login(hostiletest.Subject)

	const requests = 64
	// Hold every request after it rotated and before its UPDATE, so all of them
	// have read the same stored hash and passed the hash compare: the worst case
	// the documentation describes, with no luck of scheduling in it.
	var arrived atomic.Int64
	app.BeforeSwap = func() {
		arrived.Add(1)
		for deadline := time.Now().Add(5 * time.Second); arrived.Load() < requests && time.Now().Before(deadline); {
			runtime.Gosched()
		}
	}
	var (
		wg      sync.WaitGroup
		start   = make(chan struct{})
		winners atomic.Int64
		pairs   sync.Map
	)
	for i := 0; i < requests; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			got, err := app.Refresh(ctx, pair.RefreshToken)
			switch {
			case err == nil:
				winners.Add(1)
				pairs.Store(got.RefreshTokenHash, got)
			case errors.Is(err, hostiletest.ErrRaced), errors.Is(err, hostiletest.ErrReuse), errors.Is(err, hostiletest.ErrUnknown), errors.Is(err, jwt.ErrTokenRevoked):
				// losers: a revocation by a sibling replay may land before the library call
			default:
				t.Errorf("unexpected outcome: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()

	if got := winners.Load(); got != 1 {
		t.Fatalf("%d requests were handed a new pair, want exactly 1", got)
	}
	n := 0
	pairs.Range(func(_, _ any) bool { n++; return true })
	if n != 1 {
		t.Errorf("%d distinct pairs escaped, want 1", n)
	}
}

// Rotations and logouts of different sessions in parallel never confuse one
// session's row with another's.
func TestE2E_Race_independentSessionsRotateInParallel(t *testing.T) {
	app, _ := newApp(t, jwt.Config{})
	const sessions = 32
	type cred struct {
		pair *jwt.TokenPair
	}
	creds := make([]cred, sessions)
	for i := range creds {
		p, err := app.Login(hostiletest.Subject)
		if err != nil {
			t.Fatal(err)
		}
		creds[i] = cred{pair: p}
	}
	var wg sync.WaitGroup
	for i := range creds {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cur := creds[i].pair
			for round := 0; round < 5; round++ {
				next, err := app.Refresh(ctx, cur.RefreshToken)
				if err != nil {
					t.Errorf("session %d round %d: %v", i, round, err)
					return
				}
				if next.SessionID != cur.SessionID {
					t.Errorf("session %d changed id", i)
				}
				cur = next
			}
			if err := app.Logout(cur.RefreshToken, true); err != nil {
				t.Errorf("session %d logout: %v", i, err)
			}
		}()
	}
	wg.Wait()
	if app.Sessions.Len() != 0 {
		t.Errorf("%d rows left after every session logged out", app.Sessions.Len())
	}
}

// A thief replaying a rotated token while the client keeps refreshing: from the
// moment the replay is seen, the client's next refresh must fail, and no pair
// is ever issued for a revoked session.
func TestE2E_Race_replayWhileTheClientKeepsRefreshing(t *testing.T) {
	app, _ := newApp(t, jwt.Config{})
	pair, _ := app.Login(hostiletest.Subject)
	stolen := pair.RefreshToken
	cur, err := app.Refresh(ctx, stolen)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.Refresh(ctx, stolen); !errors.Is(err, hostiletest.ErrReuse) {
		t.Fatalf("replay = %v, want ErrReuse", err)
	}
	for i := 0; i < 5; i++ {
		if got, err := app.Refresh(ctx, cur.RefreshToken); err == nil {
			t.Fatalf("refresh %d after the replay was handed a pair %s", i, got.SessionID)
		}
	}
}
