package oauthtest

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth/internal/redirect"
)

// NewLoopbackClient returns an HTTP client whose CheckRedirect is the
// library's redirect policy (so a hand-rolled Provider that uses an http://
// loopback URL still gets the same redirect policy) and whose Transport
// rewrites the request URL onto the supplied httptest.Server.
func NewLoopbackClient(t *testing.T, srv *httptest.Server) *http.Client {
	t.Helper()
	return &http.Client{
		Transport: &loopbackTransport{URL: srv.URL},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return redirect.Check(req, via)
		},
	}
}

type loopbackTransport struct{ URL string }

func (l *loopbackTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	u, err := url.Parse(l.URL)
	if err != nil {
		return nil, err
	}
	req2 := req.Clone(req.Context())
	req2.URL.Scheme = u.Scheme
	req2.URL.Host = u.Host
	return http.DefaultTransport.RoundTrip(req2)
}
