package hostile_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
)

const remoteIssuer = "https://idp.example.com"

var endpointFields = []string{"authorization_endpoint", "token_endpoint", "jwks_uri", "userinfo_endpoint"}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// remoteDiscovery answers the discovery request of issuer with its good
// document after mutate has changed it. The transport is a function, so no
// socket is opened and the issuer is a remote name.
func remoteDiscovery(issuer string, mutate func(doc map[string]any)) *http.Client {
	doc := goodDoc(issuer)
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
