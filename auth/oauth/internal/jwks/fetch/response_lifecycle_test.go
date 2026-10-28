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

type observedBody struct {
	io.Reader
	closes int
}

func (b *observedBody) Close() error { b.closes++; return nil }

func TestGetClosesBodiesAndRecordsEveryProviderRefusalOnce(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		status int
		body   io.Reader
		wantOK bool
	}{
		{"success", 200, strings.NewReader(`{"keys":[]}`), true},
		{"status", 503, strings.NewReader(`{"keys":[]}`), false},
		{"invalid JSON", 200, strings.NewReader(`{`), false},
		{"wrong keys type", 200, strings.NewReader(`{"keys":42}`), false},
		{"read failure", 200, brokenBody{}, false},
		{"oversized", 200, strings.NewReader(`{"keys":[]}` + strings.Repeat(" ", 1<<20)), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := &observedBody{Reader: tc.body}
			client := &http.Client{Transport: stubTransport(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: tc.status, Body: body}, nil
			})}
			failures := 0
			_, err := fetch.Get(context.Background(), client, "https://provider.example/jwks", errFetch, func() { failures++ })
			wantFailures := 1
			if tc.wantOK {
				wantFailures = 0
			}
			if tc.wantOK && err != nil || !tc.wantOK && !errors.Is(err, errFetch) {
				t.Fatalf("Get = %v, want success=%v", err, tc.wantOK)
			}
			if failures != wantFailures || body.closes != 1 {
				t.Fatalf("failures=%d, closes=%d; want failures=%d and one close", failures, body.closes, wantFailures)
			}
		})
	}
}

func TestGetAcceptsOneMiBAndRefusesTheNextByteAsAProviderFailure(t *testing.T) {
	t.Parallel()
	for _, size := range []int{1 << 20, (1 << 20) + 1} {
		const prefix = `{"keys":[]}`
		failures := 0
		body := prefix + strings.Repeat(" ", size-len(prefix))
		set, err := fetch.Get(context.Background(), clientReturning(200, strings.NewReader(body)),
			"https://provider.example/jwks", errFetch, func() { failures++ })
		if size == 1<<20 {
			if err != nil || failures != 0 || len(set.Keys) != 0 {
				t.Fatalf("one MiB: set=%+v, err=%v, failures=%d", set, err, failures)
			}
		} else if !errors.Is(err, errFetch) || failures != 1 {
			t.Fatalf("one MiB plus one byte: err=%v, failures=%d", err, failures)
		}
	}
}
