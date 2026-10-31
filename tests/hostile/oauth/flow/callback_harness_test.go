package flow_test

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/oauth"
)

// The library is stateless by design: AuthCodeURL hands back State, Nonce and
// Verifier, and the caller must store them for this browser only and compare
// State on the callback (auth/oauth/authurl.go, AuthRequest.State). This is a
// minimal caller that follows that contract, so the tests can attack the
// callback leg the way a hostile browser would.

const stateTTL = 10 * time.Minute

var (
	errNoSession    = errors.New("callback: no login pending for this session")
	errStateMissing = errors.New("callback: state parameter missing")
	errStateEmpty   = errors.New("callback: state parameter empty")
	errStateRepeats = errors.New("callback: state parameter repeated")
	errStateWrong   = errors.New("callback: state does not match this session")
	errStateExpired = errors.New("callback: state expired")
)

type pendingLogin struct {
	req    *oauth.AuthRequest
	issued time.Time
}

type callbackHarness struct {
	client *oauth.Client
	mu     sync.Mutex
	now    time.Time
	byUser map[string]*pendingLogin // session id -> its one pending login
}

func newCallbackHarness(c *oauth.Client) *callbackHarness {
	return &callbackHarness{client: c, now: time.Unix(1_700_000_000, 0), byUser: map[string]*pendingLogin{}}
}

func (h *callbackHarness) advance(d time.Duration) {
	h.mu.Lock()
	h.now = h.now.Add(d)
	h.mu.Unlock()
}

// begin starts a login for session and returns the authorization URL.
func (h *callbackHarness) begin(t *testing.T, session string) *oauth.AuthRequest {
	t.Helper()
	req, err := h.client.AuthCodeURL()
	if err != nil {
		t.Fatalf("AuthCodeURL: %v", err)
	}
	h.mu.Lock()
	h.byUser[session] = &pendingLogin{req: req, issued: h.now}
	h.mu.Unlock()
	return req
}

// callback validates the state of q against session and only then calls
// Exchange. The pending login is claimed under the lock, so of two callbacks
// carrying one state exactly one gets past it.
func (h *callbackHarness) callback(ctx context.Context, session string, q url.Values) (*oauth.Tokens, *oauth.AuthRequest, error) {
	req, err := h.claim(session, q)
	if err != nil {
		return nil, nil, err
	}
	tok, err := h.client.Exchange(ctx, q.Get("code"), req.Verifier)
	return tok, req, err
}

func (h *callbackHarness) claim(session string, q url.Values) (*oauth.AuthRequest, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	p := h.byUser[session]
	if p == nil {
		return nil, errNoSession
	}
	states, present := q["state"]
	switch {
	case !present:
		return nil, errStateMissing
	case len(states) > 1:
		return nil, errStateRepeats
	case states[0] == "":
		return nil, errStateEmpty
	case subtle.ConstantTimeCompare([]byte(states[0]), []byte(p.req.State)) != 1:
		return nil, errStateWrong
	case h.now.Sub(p.issued) > stateTTL:
		delete(h.byUser, session)
		return nil, errStateExpired
	}
	delete(h.byUser, session)
	return p.req, nil
}

// redirectBack plays the provider: it asks fakeAS for a code and returns the
// query the browser is redirected to, echoing the state of the URL it got.
func redirectBack(t *testing.T, as *fakeAS, req *oauth.AuthRequest) url.Values {
	t.Helper()
	u, err := url.Parse(req.URL)
	if err != nil {
		t.Fatal(err)
	}
	return url.Values{"code": {as.authorize(t, req.URL)}, "state": {u.Query().Get("state")}}
}
