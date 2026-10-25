package hostiletest

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

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
