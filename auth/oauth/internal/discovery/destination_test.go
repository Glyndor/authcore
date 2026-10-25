package discovery

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"
)

func serving(body string) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader([]byte(body))), Request: r}, nil
	})}
}

const internalDoc = `{"issuer":"https://idp.example","authorization_endpoint":"https://idp.example/auth",` +
	`"token_endpoint":"https://10.0.0.5/token","jwks_uri":"https://idp.example/jwks"}`

func TestFetchWith_privateEndpointsNeedTheOptIn(t *testing.T) {
	t.Parallel()
	if _, err := Fetch(context.Background(), "https://idp.example", serving(internalDoc), ErrDiscovery); err == nil {
		t.Error("an internal token endpoint was accepted by default")
	}
	doc, err := FetchWith(context.Background(), "https://idp.example", serving(internalDoc), ErrDiscovery, true)
	if err != nil || doc.TokenURL != "https://10.0.0.5/token" {
		t.Errorf("opt-in: %+v, %v", doc, err)
	}
}

func TestFetchWith_loopbackIssuerMayUseLoopbackEndpoints(t *testing.T) {
	t.Parallel()
	local := `{"issuer":"http://127.0.0.1:9","authorization_endpoint":"http://127.0.0.1:9/auth",` +
		`"token_endpoint":"http://127.0.0.1:9/token","jwks_uri":"http://127.0.0.1:9/jwks"}`
	if _, err := Fetch(context.Background(), "http://127.0.0.1:9", serving(local), ErrDiscovery); err != nil {
		t.Errorf("loopback issuer: %v", err)
	}
}
