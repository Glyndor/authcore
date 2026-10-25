package hostiletest

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// IDP is a local provider endpoint that counts the requests it receives.
type IDP struct {
	*httptest.Server
	Hits atomic.Int64
}

// Serve starts a plain-HTTP loopback server (the one plaintext exception the
// library allows) whose handler is wrapped by a request counter.
func Serve(t *testing.T, h http.Handler) *IDP {
	t.Helper()
	p := &IDP{}
	p.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.Hits.Add(1)
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(p.Close)
	return p
}

// ServeTLS starts an HTTPS server and returns a client that trusts its
// certificate and nothing else.
func ServeTLS(t *testing.T, h http.Handler) (*IDP, *http.Client) {
	t.Helper()
	p := &IDP{}
	p.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.Hits.Add(1)
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(p.Close)
	pool := x509.NewCertPool()
	pool.AddCert(p.Certificate())
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
	t.Cleanup(tr.CloseIdleConnections)
	return p, &http.Client{Transport: tr}
}

// StaticBody answers every request with body as JSON.
func StaticBody(body []byte) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	})
}
