package jwks_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth/internal/jwks"
)

type authoritativeTransport func(*http.Request) (*http.Response, error)

func (h authoritativeTransport) RoundTrip(r *http.Request) (*http.Response, error) { return h(r) }

func TestKeyCoolsDownUnknownKidsAfterAnAuthoritativeEmptySet(t *testing.T) {
	t.Parallel()
	requests := 0
	client := &http.Client{Transport: authoritativeTransport(func(*http.Request) (*http.Response, error) {
		requests++
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"keys":[]}`))}, nil
	})}
	fetchError := errors.New("fetch failed")
	cache := jwks.New("https://provider.example/jwks", client, jwks.Errors{Fetch: fetchError, Stale: errors.New("stale keys")})
	for _, kid := range []string{"unknown-one", "unknown-two", "unknown-three"} {
		key, err := cache.Key(context.Background(), kid, "RS256")
		if key != nil || !errors.Is(err, fetchError) {
			t.Fatalf("unknown kid: key=%v, err=%v", key, err)
		}
		if requests != 1 {
			t.Fatalf("unknown kids caused %d fetches within one cooldown, want one", requests)
		}
	}
}
