package fetch_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth/internal/jwks/fetch"
)

type stubTransport func(*http.Request) (*http.Response, error)

func (f stubTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func clientReturning(status int, body io.Reader) *http.Client {
	return &http.Client{Transport: stubTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: status, Body: io.NopCloser(body), Header: http.Header{}}, nil
	})}
}

var errFetch = errors.New("fetch failed")

func TestGetAcceptsOnlySuccessStatuses(t *testing.T) {
	t.Parallel()
	for status, ok := range map[int]bool{199: false, 200: true, 299: true, 300: false, 301: false, 404: false, 500: false} {
		failures := 0
		_, err := fetch.Get(context.Background(), clientReturning(status, strings.NewReader(`{"keys":[]}`)),
			"https://provider.example/jwks", errFetch, func() { failures++ })
		if (err == nil) != ok {
			t.Errorf("status %d: accepted=%v, want %v (err=%v)", status, err == nil, ok, err)
		}
		if !ok && (!errors.Is(err, errFetch) || failures != 1) {
			t.Errorf("status %d: err=%v failures=%d, want a wrapped fetch error and one recorded failure", status, err, failures)
		}
	}
}

func TestGetAsksForJSON(t *testing.T) {
	t.Parallel()
	var accept string
	h := &http.Client{Transport: stubTransport(func(r *http.Request) (*http.Response, error) {
		accept = r.Header.Get("Accept")
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"keys":[]}`)), Header: http.Header{}}, nil
	})}
	if _, err := fetch.Get(context.Background(), h, "https://provider.example/jwks", errFetch, func() {}); err != nil {
		t.Fatal(err)
	}
	if accept != "application/json" {
		t.Fatalf("Accept = %q, want application/json", accept)
	}
}

type brokenBody struct{}

func (brokenBody) Read([]byte) (int, error) { return 0, errors.New("connection reset") }

func TestGetCountsAnInterruptedBodyAsAFailedAttempt(t *testing.T) {
	t.Parallel()
	failures := 0
	_, err := fetch.Get(context.Background(), clientReturning(200, brokenBody{}),
		"https://provider.example/jwks", errFetch, func() { failures++ })
	if !errors.Is(err, errFetch) || failures != 1 {
		t.Fatalf("err=%v failures=%d, want a wrapped fetch error and one recorded failure", err, failures)
	}
}
