package netguard

import (
	"net/http"
	"sync"
	"time"
)

// defaultTransport is shared by every client built without a transport of its
// own, so they share one connection pool as http.DefaultTransport does.
var defaultTransport = sync.OnceValue(func() *http.Transport {
	g := &guard{}
	return &http.Transport{
		Proxy:                 g.proxyFunc(http.ProxyFromEnvironment),
		DialContext:           g.dialer(),
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
})

// DefaultTransport is the transport of the library's default client: the
// standard library's defaults with the dial-time address check.
func DefaultTransport() http.RoundTripper { return defaultTransport() }

// Guard returns rt with the dial-time address check applied. A nil rt means
// the default transport. A *http.Transport is cloned and its dial functions
// wrapped, so the caller's own transport is left untouched. Any other
// RoundTripper cannot be inspected and is returned as is: checking where such
// a transport connects is its owner's job.
func Guard(rt http.RoundTripper) http.RoundTripper {
	if rt == nil {
		return DefaultTransport()
	}
	t, ok := rt.(*http.Transport)
	if !ok {
		return rt
	}
	if usesLegacyDial(t) {
		return rt
	}
	g := &guard{}
	c := t.Clone()
	if c.Proxy != nil {
		c.Proxy = g.proxyFunc(c.Proxy)
	}
	if c.DialContext != nil {
		c.DialContext = g.wrap(c.DialContext)
	} else {
		c.DialContext = g.dialer()
	}
	if c.DialTLSContext != nil {
		c.DialTLSContext = g.wrap(c.DialTLSContext)
	}
	return c
}

// usesLegacyDial reports whether t sets the deprecated Dial or DialTLS hooks.
// A transport that does is left to its owner: replacing DialContext next to
// them would silently change how it dials.
func usesLegacyDial(t *http.Transport) bool {
	return t.Dial != nil || t.DialTLS != nil //nolint:staticcheck // Detecting the deprecated hooks is the point.
}
