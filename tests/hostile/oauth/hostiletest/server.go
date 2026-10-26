package hostiletest

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
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

// GoodDoc is a complete, valid discovery document for the issuer base.
func GoodDoc(base string) map[string]any {
	return map[string]any{
		"issuer":                 base,
		"authorization_endpoint": base + "/auth",
		"token_endpoint":         base + "/token",
		"jwks_uri":               base + "/jwks",
		"userinfo_endpoint":      base + "/userinfo",
	}
}

// DiscoveryServer serves mutate(goodDoc) at the well-known path of a plain
// loopback server. A nil value in mutate removes the member.
func DiscoveryServer(t *testing.T, mutate func(doc map[string]any, base string)) *IDP {
	t.Helper()
	var base string
	srv := Serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc := GoodDoc(base)
		if mutate != nil {
			mutate(doc, base)
		}
		for k, v := range doc {
			if v == nil {
				delete(doc, k)
			}
		}
		_ = json.NewEncoder(w).Encode(doc)
	}))
	base = srv.URL
	return srv
}

// RemoteIssuer is a remote (non-loopback) issuer name that never resolves.
const RemoteIssuer = "https://idp.example.com"

// EndpointFields lists the discovery members that carry an endpoint URL.
var EndpointFields = []string{"authorization_endpoint", "token_endpoint", "jwks_uri", "userinfo_endpoint"}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// RemoteDiscovery answers the discovery request of issuer with its good
// document after mutate has changed it. The transport is a function, so no
// socket is opened and the issuer is a remote name.
func RemoteDiscovery(issuer string, mutate func(doc map[string]any)) *http.Client {
	doc := GoodDoc(issuer)
	mutate(doc)
	body, err := json.Marshal(doc)
	if err != nil {
		panic(err)
	}
	return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}},
			Body: io.NopCloser(bytes.NewReader(body)), Request: r,
		}, nil
	})}
}
