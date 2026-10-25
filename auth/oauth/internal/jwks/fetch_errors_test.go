package jwks

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

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
			c := New(tc.url, &http.Client{Transport: tc.rt}, testErrs)
			_, err := c.Key(context.Background(), "kid", "RS256")
			if !errors.Is(err, ErrJWKS) {
				t.Fatalf("err = %v, want errors.Is(..., ErrJWKS)", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestCandidateMatchesHonoursEveryRestriction(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		c    Candidate
		alg  string
		want bool
	}{
		{"unrestricted", Candidate{}, "RS256", true},
		{"alg pinned elsewhere", Candidate{alg: "PS256"}, "RS256", false},
		{"encryption key", Candidate{use: "enc"}, "RS256", false},
		{"verify not among key_ops", Candidate{keyOps: map[string]struct{}{"encrypt": {}}}, "RS256", false},
		{"verify among key_ops", Candidate{keyOps: map[string]struct{}{"verify": {}}}, "RS256", true},
	}
	for _, tc := range tests {
		if got := tc.c.matches(tc.alg); got != tc.want {
			t.Errorf("%s: matches(%q) = %v, want %v", tc.name, tc.alg, got, tc.want)
		}
	}
}

func TestPickCandidateNamesWhatFailed(t *testing.T) {
	t.Parallel()
	_, err := pickCandidate(ErrJWKS, nil, "", "RS256")
	if !errors.Is(err, ErrJWKS) || !strings.Contains(err.Error(), "no candidate matches alg") {
		t.Fatalf("anonymous lookup: %v", err)
	}
	_, err = pickCandidate(ErrJWKS, nil, "k1", "RS256")
	if !errors.Is(err, ErrJWKS) || !strings.Contains(err.Error(), `kid "k1"`) {
		t.Fatalf("named lookup: %v", err)
	}
}
