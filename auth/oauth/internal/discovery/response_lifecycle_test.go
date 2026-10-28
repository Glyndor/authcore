package discovery_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth/internal/discovery"
)

type observedBody struct {
	io.Reader
	closes int
}

func (b *observedBody) Close() error { b.closes++; return nil }

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestFetchClosesEveryResponseBodyBeforeReturning(t *testing.T) {
	t.Parallel()
	const issuer = "https://provider.example"
	for _, tc := range []struct {
		name   string
		status int
		body   io.Reader
		wantOK bool
	}{
		{"success", 200, strings.NewReader(document(issuer, "provider.example")), true},
		{"at size limit", 200, strings.NewReader(document(issuer, "provider.example") + strings.Repeat(" ", (1<<20)-len(document(issuer, "provider.example")))), true},
		{"status", 503, strings.NewReader(`{}`), false},
		{"invalid JSON", 200, strings.NewReader(`{`), false},
		{"read failure", 200, failingReader{}, false},
		{"oversized", 200, strings.NewReader(document(issuer, "provider.example") + strings.Repeat(" ", (1<<20)+1-len(document(issuer, "provider.example")))), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := &observedBody{Reader: tc.body}
			client := &http.Client{Transport: stub(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: tc.status, Body: body}, nil
			})}
			_, err := discovery.Fetch(context.Background(), issuer, client, errDiscovery)
			if tc.wantOK && err != nil || !tc.wantOK && !errors.Is(err, errDiscovery) {
				t.Fatalf("Fetch = %v, want success=%v", err, tc.wantOK)
			}
			if body.closes != 1 {
				t.Fatalf("response body closed %d times, want once before returning", body.closes)
			}
		})
	}
}
