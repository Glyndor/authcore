package flow_test

import (
	"errors"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/Glyndor/authcore/tests/hostile/oauth/hostiletest"
)

// Attacker: the person at the browser, or a page that can make it navigate to
// the callback (login CSRF). They deliver a callback whose state is missing,
// empty, made up, doubled, issued to another session, or old, hoping the
// caller exchanges the code anyway and logs the victim into the attacker's
// account. Effect they want: a token-endpoint call for a callback the caller
// should have refused.

// Guards auth/oauth/authurl.go:33 (a fresh state per AuthCodeURL) and :60
// (q.Set("state", state), the value the provider echoes back). With a constant
// state another session's callback matches; without it no honest callback does.
func TestHostile_Flow_callbackRejectsBadStateBeforeExchange(t *testing.T) {
	cases := []struct {
		name string
		want error
		mut  func(h *callbackHarness, q url.Values) (session string)
	}{
		{"missing", errStateMissing, func(_ *callbackHarness, q url.Values) string { q.Del("state"); return "alice" }},
		{"empty", errStateEmpty, func(_ *callbackHarness, q url.Values) string { q.Set("state", ""); return "alice" }},
		{"mismatched", errStateWrong, func(_ *callbackHarness, q url.Values) string { q.Set("state", "forged"); return "alice" }},
		{"duplicate", errStateRepeats, func(_ *callbackHarness, q url.Values) string { q.Add("state", "forged"); return "alice" }},
		{"other session", errStateWrong, func(h *callbackHarness, q url.Values) string {
			q.Set("state", h.byUser["mallory"].req.State)
			return "alice"
		}},
		{"no session", errNoSession, func(*callbackHarness, url.Values) string { return "nobody" }},
		{"expired", errStateExpired, func(h *callbackHarness, _ url.Values) string { h.advance(stateTTL + time.Second); return "alice" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, as := flowRig(t, "s3cr3t", nil)
			h := newCallbackHarness(c)
			req := h.begin(t, "alice")
			h.begin(t, "mallory")
			q := redirectBack(t, as, req)
			session := tc.mut(h, q)
			if tok, _, err := h.callback(hostiletest.Ctx(t), session, q); !errors.Is(err, tc.want) || tok != nil {
				t.Fatalf("callback = %+v, %v; want %v", tok, err, tc.want)
			}
			if n := as.tokens.Load(); n != 0 {
				t.Fatalf("%d token-endpoint calls for a refused callback, want 0", n)
			}
		})
	}
}

// Guards auth/oauth/authurl.go:33: each call issues its own state, so the
// caller's per-session comparison tells two logins apart.
func TestHostile_Flow_aStateOnlyWorksInTheSessionItWasIssuedTo(t *testing.T) {
	c, as := flowRig(t, "s3cr3t", nil)
	h := newCallbackHarness(c)
	alice, mallory := h.begin(t, "alice"), h.begin(t, "mallory")
	if alice.State == mallory.State {
		t.Fatal("two logins were issued the same state")
	}
	q := redirectBack(t, as, alice)
	if _, _, err := h.callback(hostiletest.Ctx(t), "mallory", q); !errors.Is(err, errStateWrong) {
		t.Fatalf("alice's callback in mallory's session = %v, want %v", err, errStateWrong)
	}
	if n := as.tokens.Load(); n != 0 {
		t.Fatalf("%d token-endpoint calls, want 0", n)
	}
	if _, _, err := h.callback(hostiletest.Ctx(t), "alice", q); err != nil {
		t.Fatalf("alice's own callback after the refused one: %v", err)
	}
}

// Guards auth/oauth/authurl.go:60: the state in the URL is the one returned,
// so a replay of a finished callback finds no pending login and never exchanges.
func TestHostile_Flow_replayedCallbackIsRefusedWithoutExchange(t *testing.T) {
	c, as := flowRig(t, "s3cr3t", nil)
	h := newCallbackHarness(c)
	req := h.begin(t, "alice")
	q := redirectBack(t, as, req)
	if _, _, err := h.callback(hostiletest.Ctx(t), "alice", q); err != nil {
		t.Fatalf("first callback: %v", err)
	}
	if _, _, err := h.callback(hostiletest.Ctx(t), "alice", q); !errors.Is(err, errNoSession) {
		t.Fatalf("replay = %v, want %v", err, errNoSession)
	}
	if n := as.tokens.Load(); n != 1 {
		t.Fatalf("%d token-endpoint calls, want exactly 1", n)
	}
}

// Guards auth/oauth/authurl.go:33 and :60 (the state the caller stored is the
// one the provider echoes): of two callbacks racing on one state exactly one
// wins and exactly one request reaches the token endpoint.
func TestHostile_Flow_oneWinnerWhenTwoCallbacksRaceOnOneState(t *testing.T) {
	for round := range 20 {
		c, as := flowRig(t, "s3cr3t", nil)
		h := newCallbackHarness(c)
		q := redirectBack(t, as, h.begin(t, "alice"))
		start := make(chan struct{})
		errs := make([]error, 2)
		var wg sync.WaitGroup
		for i := range errs {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				_, _, errs[i] = h.callback(hostiletest.Ctx(t), "alice", q)
			}()
		}
		close(start)
		wg.Wait()
		wins := 0
		for _, err := range errs {
			if err == nil {
				wins++
			} else if !errors.Is(err, errNoSession) {
				t.Fatalf("round %d: loser failed with %v, want %v", round, err, errNoSession)
			}
		}
		if wins != 1 || as.tokens.Load() != 1 {
			t.Fatalf("round %d: %d winners and %d token-endpoint calls, want 1 and 1", round, wins, as.tokens.Load())
		}
	}
}

// Guards auth/oauth/authurl.go:33 and :60: two logins in distinct sessions at
// once both succeed, each verified against its own nonce.
func TestHostile_Flow_simultaneousLoginsInDistinctSessionsBothSucceed(t *testing.T) {
	c, as := flowRig(t, "s3cr3t", nil)
	h := newCallbackHarness(c)
	sessions := []string{"alice", "bob"}
	queries := map[string]url.Values{}
	for _, s := range sessions {
		queries[s] = redirectBack(t, as, h.begin(t, s))
	}
	start := make(chan struct{})
	errs := make([]error, len(sessions))
	var wg sync.WaitGroup
	for i, s := range sessions {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			tok, req, err := h.callback(hostiletest.Ctx(t), s, queries[s])
			if err == nil {
				_, err = c.VerifyIDToken(hostiletest.Ctx(t), tok.IDToken, req.Nonce)
			}
			errs[i] = err
		}()
	}
	close(start)
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("%s: %v", sessions[i], err)
		}
	}
	if n := as.tokens.Load(); n != 2 {
		t.Fatalf("%d token-endpoint calls, want 2", n)
	}
}
