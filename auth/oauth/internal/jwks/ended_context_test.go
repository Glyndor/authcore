package jwks_test

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/oauth/internal/jwks"
)

type endedContextTransport struct {
	calls int
	cause error
}

func (h *endedContextTransport) RoundTrip(*http.Request) (*http.Response, error) {
	h.calls++
	return nil, h.cause
}

func TestKeyPreservesAnAlreadyEndedCallersContextWithoutFetching(t *testing.T) {
	t.Parallel()
	for _, deadline := range []bool{false, true} {
		name := "cancelled"
		if deadline {
			name = "expired"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if deadline {
				ctx, cancel = context.WithDeadline(context.Background(), time.Unix(1, 0))
				defer cancel()
			}
			fetchError := errors.New("fetch failed")
			transportError := errors.New("transport reached")
			transport := &endedContextTransport{cause: transportError}
			cache := jwks.New("https://provider.example/jwks", &http.Client{Transport: transport}, jwks.Errors{
				Fetch: fetchError, Stale: errors.New("stale keys"),
			})
			key, err := cache.Key(ctx, "absent", "RS256")
			if key != nil || !errors.Is(err, ctx.Err()) || errors.Is(err, fetchError) || transport.calls != 0 {
				t.Fatalf("ended context: key=%v, err=%v, requests=%d", key, err, transport.calls)
			}
			_, err = cache.Key(context.Background(), "absent", "RS256")
			if !errors.Is(err, fetchError) || !errors.Is(err, transportError) || transport.calls != 1 {
				t.Fatalf("live caller could not fetch: err=%v, requests=%d", err, transport.calls)
			}
		})
	}
}
