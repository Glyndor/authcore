package userinfo_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth/internal/userinfo"
)

var errUserInfo = errors.New("userinfo failed")

type stub func(*http.Request) (*http.Response, error)

func (f stub) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func serving(status int, body string, seen *http.Request) *http.Client {
	return &http.Client{Transport: stub(func(r *http.Request) (*http.Response, error) {
		if seen != nil {
			*seen = *r
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}, nil
	})}
}

func fetch(body string) error {
	_, err := userinfo.Fetch(context.Background(), serving(200, body, nil), "https://provider.example/me", "tok", errUserInfo)
	return err
}

func TestFetchAcceptsOnlySuccessStatuses(t *testing.T) {
	t.Parallel()
	for status, ok := range map[int]bool{199: false, 200: true, 299: true, 300: false, 301: false, 403: false} {
		_, err := userinfo.Fetch(context.Background(), serving(status, `{"id":1}`, nil), "https://provider.example/me", "tok", errUserInfo)
		if (err == nil) != ok {
			t.Errorf("status %d: accepted=%v, want %v (err=%v)", status, err == nil, ok, err)
		}
	}
}

// A profile may carry up to 16384 JSON tokens and nest up to 32 levels; one
// more of either is refused before the decoder builds anything.
func TestFetchProfileShapeBounds(t *testing.T) {
	t.Parallel()
	// {"a":[1,1,...]} holds 5 + n tokens for n elements.
	tokens := func(total int) string {
		return `{"a":[` + strings.TrimSuffix(strings.Repeat("1,", total-5), ",") + `]}`
	}
	nested := func(depth int) string {
		return strings.Repeat(`{"a":`, depth-1) + `{}` + strings.Repeat(`}`, depth-1)
	}
	cases := []struct {
		name string
		body string
		ok   bool
	}{
		{"16384 tokens", tokens(16384), true},
		{"16385 tokens", tokens(16385), false},
		{"depth 32", nested(32), true},
		{"depth 33", nested(33), false},
	}
	for _, c := range cases {
		if err := fetch(c.body); (err == nil) != c.ok {
			t.Errorf("%s: accepted=%v, want %v (err=%v)", c.name, err == nil, c.ok, err)
		}
	}
}

// A body that is not JSON is reported by the decoder, not mistaken for an
// oversized one.
func TestFetchLeavesMalformedBodiesToTheDecoder(t *testing.T) {
	t.Parallel()
	for _, body := range []string{`{"a":}`, `{"a" 1}`, ``} {
		err := fetch(body)
		if err == nil || !strings.Contains(err.Error(), "decode") || strings.Contains(err.Error(), "too many") {
			t.Errorf("body %q: err = %v, want a decode error", body, err)
		}
	}
}

func TestFetchAsksForJSONWithABearer(t *testing.T) {
	t.Parallel()
	var seen http.Request
	if _, err := userinfo.Fetch(context.Background(), serving(200, `{"id":1}`, &seen), "https://provider.example/me", "tok", errUserInfo); err != nil {
		t.Fatal(err)
	}
	if got := seen.Header.Get("Accept"); got != "application/json" {
		t.Errorf("Accept = %q", got)
	}
	if got := seen.Header.Get("Authorization"); got != "Bearer tok" {
		t.Errorf("Authorization = %q", got)
	}
}

func TestFetchRefusesARequestThatCannotBeBuilt(t *testing.T) {
	t.Parallel()
	var noCtx context.Context
	_, err := userinfo.Fetch(noCtx, serving(200, `{}`, nil), "https://provider.example/me", "tok", errUserInfo)
	if !errors.Is(err, errUserInfo) {
		t.Fatalf("err = %v, want the userinfo sentinel", err)
	}
}
