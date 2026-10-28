package jwks_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/Glyndor/authcore/auth/oauth/internal/jwks"
)

// A live follower can join a different initiator at every retry.
type retryContext struct {
	context.Context
	checks  atomic.Int32
	retry   chan struct{}
	proceed chan struct{}
}

func (c *retryContext) Err() error {
	if err := c.Context.Err(); err != nil {
		return err
	}
	if c.checks.Add(1)%2 == 0 {
		c.retry <- struct{}{}
		<-c.proceed
	}
	return c.Context.Err()
}

func TestLiveFollowerSurvivesRepeatedInitiatorContextEnds(t *testing.T) {
	for _, count := range []int{2, 3} {
		for _, deadline := range []bool{false, true} {
			for _, body := range []bool{false, true} {
				t.Run(fmt.Sprintf("count=%d/deadline=%v/body=%v", count, deadline, body), func(t *testing.T) {
					synctest.Test(t, func(t *testing.T) { checkRepeatedInitiators(t, count, deadline, body) })
				})
			}
		}
	}
}

func checkRepeatedInitiators(t *testing.T, count int, deadline, body bool) {
	t.Helper()
	var calls atomic.Int32
	entered := make(chan int, count+1)
	release := make(chan struct{})
	rt := memoryTransport(func(r *http.Request) (*http.Response, error) {
		n := int(calls.Add(1))
		entered <- n
		if n <= count {
			if body {
				resp := response(r, 200, "")
				resp.Body = contextBody{r.Context()}
				return resp, nil
			}
			<-r.Context().Done()
			return nil, r.Context().Err()
		}
		<-release
		return response(r, 200, keyDocument()), nil
	})
	cache := jwks.New("https://keys.example/jwks", &http.Client{Transport: rt}, jwks.Errors{Fetch: errFetch, Stale: errStale})
	followerCtx, cancelFollower := context.WithTimeout(context.Background(), time.Hour)
	defer cancelFollower()
	follower := &retryContext{Context: followerCtx, retry: make(chan struct{}, 1), proceed: make(chan struct{})}
	result := make(chan error, 1)
	for i := range count + 1 {
		ctx, cancel := context.WithCancel(context.Background())
		want := context.Canceled
		if deadline {
			cancel()
			ctx, cancel = context.WithTimeout(context.Background(), time.Second)
			want = context.DeadlineExceeded
		}
		leader := make(chan error, 1)
		go func() { _, err := cache.CandidateFor(ctx, "known", "ES256"); leader <- err }()
		if n := <-entered; n != i+1 {
			t.Fatalf("fetch = %d, want %d", n, i+1)
		}
		if i == 0 {
			go func() { _, err := cache.CandidateFor(follower, "known", "ES256"); result <- err }()
		} else {
			follower.proceed <- struct{}{}
		}
		synctest.Wait()
		if i == count {
			close(release)
			if err := <-leader; err != nil {
				t.Errorf("successful initiator: %v", err)
			}
			cancel()
			break
		}
		if deadline {
			time.Sleep(time.Second)
		} else {
			cancel()
		}
		if err := <-leader; !errors.Is(err, want) {
			t.Errorf("initiator error = %v, want %v", err, want)
		}
		cancel()
		synctest.Wait()
		select {
		case <-follower.retry:
		case err := <-result:
			t.Fatalf("live follower stopped after %d initiators: %v; own context: %v", i+1, err, followerCtx.Err())
		default:
			t.Fatal("follower did not reach the next retry")
		}
	}
	if err := <-result; err != nil {
		t.Errorf("live follower = %v", err)
	}
	if followerCtx.Err() != nil {
		t.Fatal("follower context ended")
	}
	if calls.Load() != int32(count+1) {
		t.Fatalf("fetches = %d, want %d", calls.Load(), count+1)
	}
	if _, err := cache.CandidateFor(context.Background(), "known", "ES256"); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != int32(count+1) {
		t.Fatal("cached success fetched again")
	}
}
