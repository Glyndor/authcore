package hostile_test

import (
	"bytes"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/Glyndor/authcore/auth/oauth"
)

// The time-dependent attacks (cache expiry, refresh windows, stacked
// timeouts) cannot wait out real hours. They run inside a synctest bubble,
// where time.Now and every timer are virtual and advance only when every
// goroutine is blocked, and they talk to the client through an in-memory
// http.RoundTripper, since a bubble cannot wait on a real socket. The library
// has no clock seam for this and does not need one: the bubble is the clock.

// rtFunc is an http.RoundTripper made of a function.
type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// memResponse builds a response for req without a network.
func memResponse(req *http.Request, status int, body []byte) *http.Response {
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(body)),
		Request:    req,
	}
}

// provider is a scripted in-memory identity provider. Its JWKS and token
// endpoints count the requests they get, and what they answer can be switched
// while a test runs.
type provider struct {
	jwksHits  atomic.Int64
	tokenHits atomic.Int64
	jwks      atomic.Value // []byte: the JWKS document served
	jwksFail  atomic.Bool  // answer the JWKS with a 503
	stall     atomic.Bool  // hold every request until its context ends
	token     atomic.Value // []byte: the token response served
}

func newProvider(jwks []byte) *provider {
	p := &provider{}
	p.jwks.Store(jwks)
	p.token.Store([]byte(`{}`))
	return p
}

// RoundTrip serves /jwks and treats every other path as the token endpoint.
func (p *provider) RoundTrip(req *http.Request) (*http.Response, error) {
	counter := &p.tokenHits
	if req.URL.Path == "/jwks" {
		counter = &p.jwksHits
	}
	counter.Add(1)
	if p.stall.Load() {
		<-req.Context().Done()
		return nil, req.Context().Err()
	}
	if req.URL.Path == "/jwks" {
		if p.jwksFail.Load() {
			return memResponse(req, http.StatusServiceUnavailable, []byte("down")), nil
		}
		return memResponse(req, http.StatusOK, p.jwks.Load().([]byte)), nil
	}
	return memResponse(req, http.StatusOK, p.token.Load().([]byte)), nil
}

// bubbleClient builds an OIDC client that reaches p through memory. mut may
// adjust the config (the HTTP client's timeout, for one).
func (p *provider) bubbleClient(t *testing.T, mut func(*oauth.Config)) *oauth.Client {
	t.Helper()
	return oidcClient(t, "https://idp.example/jwks", func(c *oauth.Config) {
		c.HTTPClient = &http.Client{Transport: p}
		c.Provider.TokenURL = "https://idp.example/token"
		if mut != nil {
			mut(c)
		}
	})
}

// inBubble runs f in a synctest bubble. The RSA keys are generated first,
// because key generation is real work the bubble has no reason to host.
func inBubble(t *testing.T, f func(t *testing.T)) {
	t.Helper()
	rsaKeys()
	synctest.Test(t, f)
}

// longLived are claims whose expiry outlasts the longest virtual wait here.
func longLived(over map[string]any) map[string]any {
	o := map[string]any{"exp": time.Now().Add(72 * time.Hour).Unix()}
	for k, v := range over {
		o[k] = v
	}
	return claims(testNonce, o)
}
