package jwks_test

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/Glyndor/authcore/auth/oauth/internal/jwks"
)

type contextBody struct{ ctx context.Context }

func (b contextBody) Read([]byte) (int, error) { <-b.ctx.Done(); return 0, b.ctx.Err() }
func (contextBody) Close() error               { return nil }

func TestLiveFollowersRetryAfterInitiatorContextEnds(t *testing.T) {
	for _, body := range []bool{false, true} {
		for _, deadline := range []bool{false, true} {
			for _, stale := range []bool{false, true} {
				t.Run(fmt.Sprintf("body=%v/deadline=%v/stale=%v", body, deadline, stale), func(t *testing.T) {
					synctest.Test(t, func(t *testing.T) {
						checkInitiatorContext(t, body, deadline, stale)
					})
				})
			}
		}
	}
}

func checkInitiatorContext(t *testing.T, body, deadline, stale bool) {
	t.Helper()
	var calls atomic.Int32
	block := false
	entered := make(chan struct{})
	rt := memoryTransport(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		if block {
			block = false
			close(entered)
			if body {
				resp := response(r, http.StatusOK, "")
				resp.Body = contextBody{r.Context()}
				return resp, nil
			}
			<-r.Context().Done()
			return nil, r.Context().Err()
		}
		return response(r, http.StatusOK, keyDocument()), nil
	})
	cache := jwks.New("https://keys.example/jwks", &http.Client{Transport: rt}, jwks.Errors{Fetch: errFetch, Stale: errStale})
	now := time.Now()
	jwks.SetClockForTest(cache, func() time.Time { return now })
	if stale {
		if _, err := cache.CandidateFor(context.Background(), "known", "ES256"); err != nil {
			t.Fatal(err)
		}
		now = now.Add(2 * time.Hour)
	}
	before := calls.Load()
	block = true
	ctx, cancel := context.WithCancel(context.Background())
	want := context.Canceled
	if deadline {
		cancel()
		ctx, cancel = context.WithTimeout(context.Background(), time.Second)
		want = context.DeadlineExceeded
	}
	defer cancel()
	leader := make(chan error, 1)
	go func() {
		_, err := cache.CandidateFor(ctx, "known", "ES256")
		leader <- err
	}()
	<-entered
	followers := make(chan error, 3)
	for range 3 {
		go func() {
			cand, err := cache.CandidateFor(context.Background(), "known", "ES256")
			if err == nil {
				if _, ok := cand.Pub.(*ecdsa.PublicKey); !ok {
					err = fmt.Errorf("candidate key = %T, want ECDSA", cand.Pub)
				}
			}
			followers <- err
		}()
	}
	synctest.Wait()
	if deadline {
		time.Sleep(time.Second)
	} else {
		cancel()
	}
	if err := <-leader; !errors.Is(err, want) {
		t.Errorf("initiator = %v, want %v", err, want)
	}
	for range 3 {
		if err := <-followers; err != nil {
			t.Errorf("live follower = %v, want key", err)
		}
	}
	if _, err := cache.CandidateFor(context.Background(), "known", "ES256"); err != nil {
		t.Errorf("subsequent caller = %v, want key", err)
	}
	if got := calls.Load() - before; got != 2 {
		t.Errorf("requests = %d, want 2", got)
	}
}

func TestProviderContextErrorsKeepCooldown(t *testing.T) {
	for _, body := range []bool{false, true} {
		t.Run(fmt.Sprintf("body=%v", body), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var calls atomic.Int32
				entered := make(chan struct{})
				rt := memoryTransport(func(r *http.Request) (*http.Response, error) {
					if calls.Add(1) == 1 {
						close(entered)
					}
					if body {
						resp := response(r, http.StatusOK, "")
						resp.Body = contextBody{r.Context()}
						return resp, nil
					}
					<-r.Context().Done()
					return nil, r.Context().Err()
				})
				cache := jwks.New("https://keys.example/jwks", &http.Client{Transport: rt, Timeout: time.Second}, jwks.Errors{Fetch: errFetch, Stale: errStale})
				result := make(chan error, 2)
				lookup := func() {
					_, err := cache.CandidateFor(context.Background(), "known", "ES256")
					result <- err
				}
				go lookup()
				<-entered
				go lookup()
				synctest.Wait()
				time.Sleep(time.Second)
				for range 2 {
					if err := <-result; !errors.Is(err, errFetch) || !errors.Is(err, context.DeadlineExceeded) {
						t.Errorf("provider timeout = %v, want fetch error with deadline cause", err)
					}
				}
				if _, err := cache.CandidateFor(context.Background(), "known", "ES256"); !errors.Is(err, errFetch) {
					t.Errorf("cooldown error = %v, want fetch refusal", err)
				}
				if got := calls.Load(); got != 1 {
					t.Errorf("requests = %d, want 1", got)
				}
			})
		})
	}
}
