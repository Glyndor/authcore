package hostiletest

import (
	"bytes"
	"io"
	"maps"
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

// RTFunc is an http.RoundTripper made of a function.
type RTFunc func(*http.Request) (*http.Response, error)

// RoundTrip calls f.
func (f RTFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// MemResponse builds a response for req without a network.
func MemResponse(req *http.Request, status int, body []byte) *http.Response {
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(body)),
		Request:    req,
	}
}

// MemProvider is a scripted in-memory identity provider. Its JWKS and token
// endpoints count the requests they get, and what they answer can be switched
// while a test runs.
type MemProvider struct {
	JWKSHits  atomic.Int64
	tokenHits atomic.Int64
	JWKS      atomic.Value // []byte: the JWKS document served
	JWKSFail  atomic.Bool  // answer the JWKS with a 503
	Stall     atomic.Bool  // hold every request until its context ends
	token     atomic.Value // []byte: the token response served
}

// NewMemProvider returns a provider that serves jwks and answers tokens with {}.
func NewMemProvider(jwks []byte) *MemProvider {
	p := &MemProvider{}
	p.JWKS.Store(jwks)
	p.token.Store([]byte(`{}`))
	return p
}

// RoundTrip serves /jwks and treats every other path as the token endpoint.
func (p *MemProvider) RoundTrip(req *http.Request) (*http.Response, error) {
	counter := &p.tokenHits
	if req.URL.Path == "/jwks" {
		counter = &p.JWKSHits
	}
	counter.Add(1)
	if p.Stall.Load() {
		<-req.Context().Done()
		return nil, req.Context().Err()
	}
	if req.URL.Path == "/jwks" {
		if p.JWKSFail.Load() {
			return MemResponse(req, http.StatusServiceUnavailable, []byte("down")), nil
		}
		return MemResponse(req, http.StatusOK, p.JWKS.Load().([]byte)), nil
	}
	return MemResponse(req, http.StatusOK, p.token.Load().([]byte)), nil
}

// BubbleClient builds an OIDC client that reaches p through memory. mut may
// adjust the config (the HTTP client's timeout, for one).
func (p *MemProvider) BubbleClient(t *testing.T, mut func(*oauth.Config)) *oauth.Client {
	t.Helper()
	return OIDCClient(t, "https://idp.example/jwks", func(c *oauth.Config) {
		c.HTTPClient = &http.Client{Transport: p}
		c.Provider.TokenURL = "https://idp.example/token"
		if mut != nil {
			mut(c)
		}
	})
}

// InBubble runs f in a synctest bubble. The RSA keys are generated first,
// because key generation is real work the bubble has no reason to host.
func InBubble(t *testing.T, f func(t *testing.T)) {
	t.Helper()
	RSAKeys()
	synctest.Test(t, f)
}

// LongLived are claims whose expiry outlasts the longest virtual wait here.
func LongLived(over map[string]any) map[string]any {
	o := map[string]any{"exp": time.Now().Add(72 * time.Hour).Unix()}
	maps.Copy(o, over)
	return Claims(Nonce, o)
}
