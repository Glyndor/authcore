package userinfo

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

var errUserInfo = errors.New("oauth: userinfo request failed")

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type brokenBody struct{}

func (brokenBody) Read([]byte) (int, error) { return 0, errors.New("connection reset") }
func (brokenBody) Close() error             { return nil }

func respond(code int, body string) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
}

func TestFetchReturnsTheProfileWithBearerAndNumbers(t *testing.T) {
	t.Parallel()
	var gotAuth, gotAccept string
	h := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		gotAuth, gotAccept = r.Header.Get("Authorization"), r.Header.Get("Accept")
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"id":9007199254740993,"login":"octo"}`))}, nil
	})}
	out, err := Fetch(context.Background(), h, "https://api.example/user", "tok", errUserInfo)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if gotAuth != "Bearer tok" || gotAccept != "application/json" {
		t.Errorf("headers: Authorization=%q Accept=%q", gotAuth, gotAccept)
	}
	if id, ok := out["id"].(json.Number); !ok || id.String() != "9007199254740993" {
		t.Errorf("id = %#v, want the exact json.Number", out["id"])
	}
}

func TestFetchRefusals(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		endpoint string
		token    string
		client   *http.Client
		want     string
	}{
		{"empty token", "https://api.example/u", "", respond(200, `{"id":1}`), "access token must not be empty"},
		{"unbuildable request", "http://\x7f/u", "t", respond(200, `{"id":1}`), "build request"},
		{"transport error", "https://api.example/u", "t", &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("dial failed")
		})}, "dial failed"},
		{"read error", "https://api.example/u", "t", &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: brokenBody{}}, nil
		})}, "read:"},
		{"non-2xx", "https://api.example/u", "t", respond(401, `{"id":1}`), "status 401"},
		{"undecodable", "https://api.example/u", "t", respond(200, `{`), "decode:"},
		{"trailing data", "https://api.example/u", "t", respond(200, `{"id":1} {"id":2}`), "trailing data"},
		{"null body", "https://api.example/u", "t", respond(200, `null`), "response was null"},
		{"not an object", "https://api.example/u", "t", respond(200, `[1]`), "decode:"},
		{"error object", "https://api.example/u", "t", respond(200, `{"error":"bad_token"}`), "error object"},
		{"empty profile", "https://api.example/u", "t", respond(200, `{}`), "empty profile"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := Fetch(context.Background(), tc.client, tc.endpoint, tc.token, errUserInfo)
			if !errors.Is(err, errUserInfo) {
				t.Fatalf("err = %v, want errors.Is(..., errUserInfo)", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}
