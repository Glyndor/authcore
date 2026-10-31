package timing_test

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/oauth"
	"github.com/Glyndor/authcore/tests/hostile/oauth/hostiletest"
)

// Attacker: callers that start the shared JWKS refresh and cancel it while an
// honest caller waits on it, hoping the honest caller inherits the cancellation
// (a denial of the rotated key), or that the churn leaves a forged key cached.

// churnRig is a provider whose second JWKS fetch stalls until its own
// context ends; every other fetch answers at once.
type churnRig struct {
	calls   atomic.Int32
	entered chan struct{}
	first   []byte
	rotated []byte
}

func newChurnRig() *churnRig {
	a, b := hostiletest.RSAKeys()
	return &churnRig{
		entered: make(chan struct{}),
		first:   hostiletest.JWKSDoc(hostiletest.RSAJWK("k1", &a.PublicKey, nil)),
		rotated: hostiletest.JWKSDoc(hostiletest.RSAJWK("k2", &b.PublicKey, nil)),
	}
}

func (r *churnRig) RoundTrip(req *http.Request) (*http.Response, error) {
	switch r.calls.Add(1) {
	case 1:
		return hostiletest.MemResponse(req, http.StatusOK, r.first), nil
	case 2:
		close(r.entered)
		<-req.Context().Done()
		return nil, req.Context().Err()
	}
	return hostiletest.MemResponse(req, http.StatusOK, r.rotated), nil
}

func (r *churnRig) client(t *testing.T) *oauth.Client {
	t.Helper()
	return hostiletest.OIDCClient(t, "https://idp.example/jwks", func(c *oauth.Config) {
		c.HTTPClient = &http.Client{Transport: r}
	})
}

type verdict struct {
	claims *oauth.IDClaims
	err    error
}

func verifyAsync(t *testing.T, c *oauth.Client, ctx context.Context, token string) <-chan verdict {
	t.Helper()
	out := make(chan verdict, 1)
	go func() {
		got, err := c.VerifyIDToken(ctx, token, hostiletest.Nonce)
		out <- verdict{got, err}
	}()
	return out
}

func mustBeCancelled(t *testing.T, who string, v verdict) {
	t.Helper()
	if v.err == nil || !errors.Is(v.err, context.Canceled) {
		t.Errorf("%s: %v (claims %+v), want a cancelled caller rejected", who, v.err, v.claims)
	}
}

// Guards auth/oauth/internal/jwks/jwks.go:133-141, the loop that re-fetches
// for a live caller whose shared flight died with its initiator's context.
// Without it the honest follower returns the initiator's cancellation.
func TestHostile_JWKS_cancelChurn_honestFollowerSurvivesCancelledInitiators(t *testing.T) {
	hostiletest.InBubble(t, func(t *testing.T) {
		a, b := hostiletest.RSAKeys()
		rig := newChurnRig()
		c := rig.client(t)
		if _, err := hostiletest.Verify(t, c, hostiletest.SignA(t, hostiletest.LongLived(nil))); err != nil {
			t.Fatalf("prime: %v", err)
		}
		time.Sleep(2 * time.Minute) // past the unknown-kid cooldown, inside the TTL
		honest := hostiletest.Mint{Key: b, Kid: "k2", Claims: hostiletest.LongLived(nil)}.String(t)
		forged := hostiletest.Mint{Key: a, Kid: "k2", Claims: hostiletest.LongLived(nil)}.String(t)

		leaderCtx, cancelLeader := context.WithCancel(context.Background())
		defer cancelLeader()
		leader := verifyAsync(t, c, leaderCtx, forged)
		<-rig.entered
		follower := verifyAsync(t, c, hostiletest.Ctx(t), honest)
		var churn []<-chan verdict
		var cancels []context.CancelFunc
		for range 3 {
			ctx, cancel := context.WithCancel(context.Background())
			cancels = append(cancels, cancel)
			churn = append(churn, verifyAsync(t, c, ctx, forged))
		}
		time.Sleep(time.Second)
		for i, cancel := range cancels {
			cancel()
			mustBeCancelled(t, "joined churner", <-churn[i])
		}
		cancelLeader()
		mustBeCancelled(t, "initiator", <-leader)
		if v := <-follower; v.err != nil || v.claims == nil {
			t.Fatalf("honest follower poisoned by the cancellations: %v", v.err)
		}
		if n := rig.calls.Load(); n != 3 {
			t.Fatalf("%d fetches, want 3 (prime, cancelled flight, one more)", n)
		}
		got, err := hostiletest.Verify(t, c, forged)
		hostiletest.MustRejectToken(t, got, err)
		for _, kid := range []string{"ghost", "k1"} {
			tok := hostiletest.Mint{Key: a, Kid: kid, Claims: hostiletest.LongLived(nil)}.String(t)
			got, err := hostiletest.Verify(t, c, tok)
			hostiletest.MustRejectToken(t, got, err)
		}
		if n := rig.calls.Load(); n != 3 {
			t.Fatalf("forged tokens caused %d fetches in total, want 3", n)
		}
		if _, err := hostiletest.Verify(t, c, honest); err != nil {
			t.Fatalf("rotated key lost after the churn: %v", err)
		}
	})
}

// Guards auth/oauth/internal/jwks/jwks.go:134 (!errors.Is(err, c.errs.Fetch)):
// a deadline that is the provider's own, the HTTP client timeout, is a
// provider failure, so it keeps the one-minute cooldown instead of being
// retried by the callers that waited on it.
func TestHostile_JWKS_cancelChurn_providerTimeoutKeepsItsCooldown(t *testing.T) {
	hostiletest.InBubble(t, func(t *testing.T) {
		a, _ := hostiletest.RSAKeys()
		p := hostiletest.NewMemProvider(hostiletest.JWKSDoc(hostiletest.RSAJWK("k1", &a.PublicKey, nil)))
		c := p.BubbleClient(t, func(cfg *oauth.Config) {
			cfg.HTTPClient = &http.Client{Transport: p, Timeout: time.Second}
		})
		p.Stall.Store(true)
		tok := hostiletest.SignA(t, hostiletest.LongLived(nil))
		first := verifyAsync(t, c, context.Background(), tok)
		second := verifyAsync(t, c, context.Background(), tok)
		for _, r := range []<-chan verdict{first, second} {
			v := <-r
			if v.err == nil {
				t.Fatalf("stalled provider accepted a token: %+v", v.claims)
			}
			if !errors.Is(v.err, context.DeadlineExceeded) {
				t.Errorf("waiter = %v, want the provider timeout as its cause, not a retried cooldown", v.err)
			}
		}
		if n := p.JWKSHits.Load(); n != 1 {
			t.Fatalf("the timeout was retried: %d fetches, want 1", n)
		}
		got, err := hostiletest.Verify(t, c, tok)
		hostiletest.MustRejectToken(t, got, err)
		time.Sleep(30 * time.Second)
		got, err = hostiletest.Verify(t, c, tok)
		hostiletest.MustRejectToken(t, got, err)
		if n := p.JWKSHits.Load(); n != 1 {
			t.Fatalf("inside the cooldown: %d fetches, want 1", n)
		}
		p.Stall.Store(false)
		time.Sleep(time.Minute)
		if _, err := hostiletest.Verify(t, c, tok); err != nil {
			t.Fatalf("after the cooldown: %v", err)
		}
		if n := p.JWKSHits.Load(); n != 2 {
			t.Fatalf("after the cooldown: %d fetches, want 2", n)
		}
	})
}
