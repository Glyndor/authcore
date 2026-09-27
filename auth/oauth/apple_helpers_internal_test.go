package oauth

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// newLoopbackClient returns an HTTP client whose CheckRedirect is the
// library's safeRedirect (so a hand-rolled Provider that uses an http://
// loopback URL still gets the same redirect policy) and whose Transport
// rewrites the request URL onto the supplied httptest.Server.
func newLoopbackClient(t *testing.T, srv *httptest.Server) *http.Client {
	t.Helper()
	return &http.Client{
		Transport: &loopbackTransport{URL: srv.URL},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return safeRedirect(req, via)
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

// appleBase64Body returns the base64 body of the first PEM block in p8, or
// "" when p8 is not a PEM document. Used by tests to assert no 16-byte
// substring of the key material leaks through any error message.
func appleBase64Body(p8 []byte) string {
	for {
		i := bytes.Index(p8, []byte("-----BEGIN "))
		if i < 0 {
			return ""
		}
		end := bytes.Index(p8[i:], []byte("-----END "))
		if end < 0 {
			return ""
		}
		tail := p8[i+end:]
		fin := bytes.Index(tail, []byte("-----"))
		if fin < 0 {
			return ""
		}
		block := p8[i : i+end+fin+5]
		p8 = p8[i+end+fin+5:]
		eol := bytes.Index(block, []byte("\n"))
		if eol < 0 {
			continue
		}
		body := block[eol+1:]
		idx := bytes.Index(body, []byte("-----END "))
		if idx < 0 {
			continue
		}
		body = body[:idx]
		body = bytes.ReplaceAll(body, []byte("\n"), nil)
		body = bytes.ReplaceAll(body, []byte("\r"), nil)
		return string(body)
	}
}
