package fetch

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

var errFetch = errors.New("oauth: cannot obtain provider signing keys")

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// failingBody reports a read error after the headers were accepted.
type failingBody struct{}

func (failingBody) Read([]byte) (int, error) { return 0, errors.New("connection reset") }
func (failingBody) Close() error             { return nil }

func TestFetchFailuresWrapTheFetchSentinel(t *testing.T) {
	t.Parallel()
	status := func(code int, body string) http.RoundTripper {
		return roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(body))}, nil
		})
	}
	tests := []struct {
		name string
		url  string
		rt   http.RoundTripper
		want string
	}{
		{"unbuildable request", "http://\x7f/jwks", status(200, "{}"), "build request"},
		{"body read error", "https://keys.example/jwks", roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: failingBody{}}, nil
		}), "read:"},
		{"non-2xx", "https://keys.example/jwks", status(503, ""), "status 503"},
		{"undecodable", "https://keys.example/jwks", status(200, "not json"), "decode:"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := Get(context.Background(), &http.Client{Transport: tc.rt}, tc.url, errFetch, func() {})
			if !errors.Is(err, errFetch) {
				t.Fatalf("err = %v, want errors.Is(..., errFetch)", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}
