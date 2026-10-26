package hostiletest_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/oauth"
	"github.com/Glyndor/authcore/tests/hostile/oauth/hostiletest"
)

func get(t *testing.T, rt http.RoundTripper, ctx context.Context, url string) (int, string, error) {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := rt.RoundTrip(req)
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), nil
}

func TestMemResponseAndRTFunc(t *testing.T) {
	var rt http.RoundTripper = hostiletest.RTFunc(func(r *http.Request) (*http.Response, error) {
		return hostiletest.MemResponse(r, http.StatusTeapot, []byte("tea")), nil
	})
	code, body, err := get(t, rt, context.Background(), "https://idp.example/x")
	if err != nil || code != http.StatusTeapot || body != "tea" {
		t.Fatalf("got %d %q %v", code, body, err)
	}
}

func TestMemProviderInTheBubble(t *testing.T) {
	jwks := []byte(`{"keys":[]}`)
	hostiletest.InBubble(t, func(t *testing.T) {
		p := hostiletest.NewMemProvider(jwks)
		ctx := context.Background()

		if code, body, err := get(t, p, ctx, "https://idp.example/jwks"); err != nil || code != 200 || body != string(jwks) {
			t.Fatalf("jwks: %d %q %v", code, body, err)
		}
		if code, body, err := get(t, p, ctx, "https://idp.example/token"); err != nil || code != 200 || body != "{}" {
			t.Fatalf("token: %d %q %v", code, body, err)
		}
		p.JWKSFail.Store(true)
		if code, _, err := get(t, p, ctx, "https://idp.example/jwks"); err != nil || code != http.StatusServiceUnavailable {
			t.Fatalf("failing jwks: %d %v", code, err)
		}
		p.JWKSFail.Store(false)

		p.Stall.Store(true)
		short, cancel := context.WithTimeout(ctx, time.Hour)
		defer cancel()
		start := time.Now()
		if _, _, err := get(t, p, short, "https://idp.example/jwks"); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("a stalled request must end with its context: %v", err)
		}
		if time.Since(start) != time.Hour {
			t.Fatalf("virtual time advanced %v, want 1h", time.Since(start))
		}
		p.Stall.Store(false)

		if p.JWKSHits.Load() != 3 {
			t.Fatalf("jwks hits = %d, want 3", p.JWKSHits.Load())
		}
		c := p.BubbleClient(t, func(c *oauth.Config) { c.HTTPClient.Timeout = time.Minute })
		if c == nil {
			t.Fatal("BubbleClient returned nil")
		}
		if p.BubbleClient(t, nil) == nil {
			t.Fatal("BubbleClient(nil) returned nil")
		}
	})
}
