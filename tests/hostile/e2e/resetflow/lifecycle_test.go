package resetflow

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/credential"
	"github.com/Glyndor/authcore/tests/hostile/e2e/hostiletest"
)

// The edge of the window, one nanosecond at a time. issuedAt is taken from the
// same clock the module reads, so the elapsed time at Verify is the TTL plus
// the few nanoseconds between the two reads: never inside the window.
func TestE2E_Reset_aTokenIsGoneTheInstantItsTTLHasPassed(t *testing.T) {
	w := newWorld(t)
	token := w.issue(t, w.resets, "reset", "alice", time.Now())
	row, _ := w.resets.Get("alice")

	for _, d := range []time.Duration{time.Nanosecond, time.Microsecond, time.Millisecond, time.Second, time.Hour} {
		issuedAt := time.Now().Add(-ttl - d)
		if err := w.cred.Verify("reset", "alice", token, row.Hash, issuedAt); !errors.Is(err, credential.ErrExpired) {
			t.Errorf("issued ttl+%s ago = %v, want ErrExpired", d, err)
		}
	}
	// issuedAt taken before the call, so elapsed is ttl plus the call's own
	// latency, however small.
	if err := w.cred.Verify("reset", "alice", token, row.Hash, time.Now().Add(-ttl)); !errors.Is(err, credential.ErrExpired) {
		t.Errorf("issued exactly ttl ago = %v, want ErrExpired", err)
	}
	for _, d := range []time.Duration{time.Second, time.Minute, ttl - time.Minute} {
		if err := w.cred.Verify("reset", "alice", token, row.Hash, time.Now().Add(-d)); err != nil {
			t.Errorf("issued %s ago = %v, want accepted", d, err)
		}
	}
}

// A stored timestamp from the future is a corrupt or forged row, not a token
// with extra life: beyond the minute of skew it is refused.
func TestE2E_Reset_aTimestampFromTheFutureIsNotExtraLife(t *testing.T) {
	w := newWorld(t)
	token := w.issue(t, w.resets, "reset", "alice", time.Now())
	row, _ := w.resets.Get("alice")
	for name, at := range map[string]time.Time{
		"30s ahead (clock skew)": time.Now().Add(30 * time.Second),
	} {
		if err := w.cred.Verify("reset", "alice", token, row.Hash, at); err != nil {
			t.Errorf("%s = %v, want accepted", name, err)
		}
	}
	for name, at := range map[string]time.Time{
		"2m ahead": time.Now().Add(2 * time.Minute), "a day ahead": time.Now().Add(24 * time.Hour),
		"zero time": {}, "far future": time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC),
	} {
		if err := w.cred.Verify("reset", "alice", token, row.Hash, at); !errors.Is(err, credential.ErrExpired) {
			t.Errorf("%s = %v, want ErrExpired", name, err)
		}
	}
}

// Single use through the application's statement, and what re-issuing does: a
// second mail replaces the first row, so the first token dies before any use.
func TestE2E_Reset_usedOnceAndReplacedByTheNextIssue(t *testing.T) {
	w := newWorld(t)
	first := w.issue(t, w.resets, "reset", "alice", time.Now())
	second := w.issue(t, w.resets, "reset", "alice", time.Now())
	if first == second {
		t.Fatal("two issues returned one token")
	}
	if err := w.resets.Redeem(w.cred, "reset", "alice", first); !errors.Is(err, credential.ErrInvalidCredential) {
		t.Errorf("the replaced token = %v, want ErrInvalidCredential", err)
	}
	if err := w.resets.Redeem(w.cred, "reset", "alice", second); err != nil {
		t.Fatalf("the current token = %v, want accepted", err)
	}
	if err := w.resets.Redeem(w.cred, "reset", "alice", second); !errors.Is(err, hostiletest.ErrNoRow) {
		t.Errorf("the spent token = %v, want ErrNoRow", err)
	}
	// An attacker who copied the token before it was spent, and who replays it
	// after the application issued a NEW token for the next reset, gets nothing.
	third := w.issue(t, w.resets, "reset", "alice", time.Now())
	if err := w.resets.Redeem(w.cred, "reset", "alice", second); !errors.Is(err, credential.ErrInvalidCredential) {
		t.Errorf("the spent token against a newer row = %v, want ErrInvalidCredential", err)
	}
	if err := w.resets.Redeem(w.cred, "reset", "alice", third); err != nil {
		t.Errorf("the newest token = %v, want accepted", err)
	}
}

// Changing the password must invalidate the pending reset (credential.md,
// footgun 2): the application deletes the row, and the module has no memory to
// object.
func TestE2E_Reset_deletingTheRowKillsThePendingToken(t *testing.T) {
	w := newWorld(t)
	token := w.issue(t, w.resets, "reset", "alice", time.Now())
	row, _ := w.resets.Get("alice")
	if !w.resets.Consume("alice", row.Hash) {
		t.Fatal("the delete did not remove the row")
	}
	if err := w.resets.Redeem(w.cred, "reset", "alice", token); !errors.Is(err, hostiletest.ErrNoRow) {
		t.Errorf("token after the password change = %v, want ErrNoRow", err)
	}
	// The module alone, handed the old hash, still says yes: single use and
	// invalidation are the application's half.
	if err := w.cred.Verify("reset", "alice", token, row.Hash, time.Now()); err != nil {
		t.Errorf("module over the retained hash = %v, want accepted (stateless)", err)
	}
}

// Many requests redeem one valid token at once: exactly one is accepted, and
// the row is gone afterwards.
func TestE2E_Reset_concurrentRedemptionYieldsOneWinner(t *testing.T) {
	w := newWorld(t)
	token := w.issue(t, w.resets, "reset", "alice", time.Now())
	const requests = 64
	var (
		wg      sync.WaitGroup
		start   = make(chan struct{})
		winners atomic.Int64
	)
	for i := 0; i < requests; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			switch err := w.resets.Redeem(w.cred, "reset", "alice", token); {
			case err == nil:
				winners.Add(1)
			case errors.Is(err, hostiletest.ErrConsumed), errors.Is(err, hostiletest.ErrNoRow):
			default:
				t.Errorf("unexpected outcome: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()
	if got := winners.Load(); got != 1 {
		t.Fatalf("%d redemptions accepted, want exactly 1", got)
	}
	if w.resets.Len() != 0 {
		t.Error("row still pending after a successful redemption")
	}
}

// The same subject redeems a reset and an activation at the same time, each
// with its own token, and attackers cross the two tokens over the endpoints:
// each endpoint accepts its own token once, and only that.
func TestE2E_Reset_concurrentPurposesForOneSubjectStayApart(t *testing.T) {
	w := newWorld(t)
	resetToken := w.issue(t, w.resets, "reset", "alice", time.Now())
	activateToken := w.issue(t, w.activation, "activate", "alice", time.Now())

	var (
		wg     sync.WaitGroup
		start  = make(chan struct{})
		wins   [2]atomic.Int64
		crosse atomic.Int64
	)
	run := func(fn func() error, win *atomic.Int64) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if fn() == nil {
				win.Add(1)
			}
		}()
	}
	for i := 0; i < 16; i++ {
		run(func() error { return w.resets.Redeem(w.cred, "reset", "alice", resetToken) }, &wins[0])
		run(func() error { return w.activation.Redeem(w.cred, "activate", "alice", activateToken) }, &wins[1])
		run(func() error { return w.resets.Redeem(w.cred, "reset", "alice", activateToken) }, &crosse)
		run(func() error { return w.activation.Redeem(w.cred, "activate", "alice", resetToken) }, &crosse)
	}
	close(start)
	wg.Wait()
	if wins[0].Load() != 1 || wins[1].Load() != 1 {
		t.Errorf("reset wins=%d activation wins=%d, want 1 and 1", wins[0].Load(), wins[1].Load())
	}
	if crosse.Load() != 0 {
		t.Errorf("%d crossed redemptions were accepted, want 0", crosse.Load())
	}
}
