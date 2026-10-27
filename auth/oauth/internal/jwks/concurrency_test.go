package jwks_test

import (
	"context"
	"crypto/elliptic"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/Glyndor/authcore/auth/oauth/internal/jwks"
)

var errFetch = errors.New("jwks fetch")
var errStale = errors.New("jwks stale")

type memoryTransport func(*http.Request) (*http.Response, error)

func (f memoryTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func keyDocument() string {
	p := elliptic.P256().Params()
	x := base64.RawURLEncoding.EncodeToString(p.Gx.FillBytes(make([]byte, 32)))
	y := base64.RawURLEncoding.EncodeToString(p.Gy.FillBytes(make([]byte, 32)))
	return fmt.Sprintf(`{"keys":[{"kty":"EC","crv":"P-256","kid":"known","x":%q,"y":%q}]}`, x, y)
}

func response(r *http.Request, status int, doc string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header),
		Body: io.NopCloser(strings.NewReader(doc)), Request: r}
}

func TestCandidateForRespectsRefreshCooldown(t *testing.T) {
	for _, known := range []bool{false, true} {
		t.Run(fmt.Sprintf("known=%v", known), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var calls atomic.Int32
				down := false
				rt := memoryTransport(func(r *http.Request) (*http.Response, error) {
					calls.Add(1)
					if down {
						return response(r, http.StatusServiceUnavailable, ""), nil
					}
					return response(r, http.StatusOK, keyDocument()), nil
				})
				cache := jwks.New("https://keys.example/jwks", &http.Client{Transport: rt}, jwks.Errors{Fetch: errFetch, Stale: errStale})
				now := time.Now()
				jwks.SetClockForTest(cache, func() time.Time { return now })
				kid := "missing"
				if known {
					kid = "known"
					if _, err := cache.CandidateFor(context.Background(), kid, "ES256"); err != nil {
						t.Fatal(err)
					}
					now = now.Add(2 * time.Hour)
				}
				down = true
				before := calls.Load()
				entered, resume := make(chan struct{}), make(chan struct{})
				var reads atomic.Int32
				jwks.SetClockForTest(cache, func() time.Time {
					if reads.Add(1) == 1 {
						close(entered)
						<-resume
					}
					return now
				})
				result := make(chan error, 1)
				go func() {
					_, err := cache.CandidateFor(context.Background(), kid, "ES256")
					result <- err
				}()
				<-entered
				_, first := cache.CandidateFor(context.Background(), kid, "ES256")
				close(resume)
				second := <-result
				for _, err := range []error{first, second} {
					if !errors.Is(err, errFetch) || (known && !errors.Is(err, errStale)) {
						t.Errorf("lookup error = %v, want fetch refusal (stale=%v)", err, known)
					}
				}
				if got := calls.Load() - before; got != 1 {
					t.Errorf("requests during cooldown = %d, want 1", got)
				}
				now = now.Add(time.Minute)
				down = false
				_, err := cache.CandidateFor(context.Background(), "known", "ES256")
				if err != nil || calls.Load()-before != 2 {
					t.Errorf("after cooldown: err=%v, requests=%d, want key and 2", err, calls.Load()-before)
				}
			})
		})
	}
}

func TestCandidateForFollowerRespectsContext(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		t.Run(fmt.Sprintf("deadline=%v", deadline), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				entered, release := make(chan struct{}), make(chan struct{})
				var calls atomic.Int32
				rt := memoryTransport(func(r *http.Request) (*http.Response, error) {
					if calls.Add(1) == 1 {
						close(entered)
					}
					select {
					case <-release:
						return response(r, http.StatusOK, keyDocument()), nil
					case <-r.Context().Done():
						return nil, r.Context().Err()
					}
				})
				cache := jwks.New("https://keys.example/jwks", &http.Client{Transport: rt}, jwks.Errors{Fetch: errFetch, Stale: errStale})
				leader := make(chan error, 1)
				go func() {
					_, err := cache.CandidateFor(context.Background(), "known", "ES256")
					leader <- err
				}()
				<-entered
				ctx, cancel := context.WithCancel(context.Background())
				want := context.Canceled
				if deadline {
					cancel()
					ctx, cancel = context.WithTimeout(context.Background(), time.Second)
					want = context.DeadlineExceeded
				}
				defer cancel()
				follower := make(chan error, 1)
				go func() {
					_, err := cache.CandidateFor(ctx, "known", "ES256")
					follower <- err
				}()
				synctest.Wait()
				if deadline {
					time.Sleep(time.Second)
				} else {
					cancel()
				}
				synctest.Wait()
				select {
				case err := <-follower:
					if !errors.Is(err, want) {
						t.Errorf("follower error = %v, want %v", err, want)
					}
				default:
					t.Error("follower still waiting after its context ended")
				}
				select {
				case err := <-leader:
					t.Errorf("shared fetch ended before release: %v", err)
				default:
				}
				close(release)
				if err := <-leader; err != nil {
					t.Errorf("leader: %v", err)
				}
				if got := calls.Load(); got != 1 {
					t.Errorf("shared fetch requests = %d, want 1", got)
				}
			})
		})
	}
}
