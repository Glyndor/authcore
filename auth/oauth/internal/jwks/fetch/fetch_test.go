package fetch

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func serve(t *testing.T, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func get(t *testing.T, body string) Set {
	t.Helper()
	srv := serve(t, body)
	set, err := Get(context.Background(), srv.Client(), srv.URL, errFetch, func() { t.Error("a good fetch must not count as a failed attempt") })
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	return set
}

// rsaN is the modulus of a freshly generated RSA key, base64url-encoded.
var rsaN = base64.RawURLEncoding.EncodeToString(func() []byte {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return k.N.Bytes()
}())

// Get keeps signature keys grouped by kid, drops what cannot verify a token,
// and counts none of it as a failed attempt.
func TestGetBuildsTheCandidateSet(t *testing.T) {
	set := get(t, `{"keys":[
		{"kty":"RSA","kid":"sig","n":"`+rsaN+`","e":"AQAB","alg":"RS256","use":"sig","key_ops":["verify"],"issuer":"https://p.example"},
		{"kty":"RSA","kid":"enc","n":"`+rsaN+`","e":"AQAB","use":"enc"},
		{"kty":"oct","kid":"unusable"},
		{"kty":"RSA","kid":"sig","n":"`+rsaN+`","e":"AQAB"}
	]}`)

	if set.AnonAvailable {
		t.Error("AnonAvailable = true, want false: every usable key has a kid")
	}
	if len(set.Keys) != 1 || len(set.Keys["sig"]) != 2 {
		t.Fatalf("Keys = %v, want only the two candidates under kid %q", set.Keys, "sig")
	}
	c := set.Keys["sig"][0]
	if c.Alg != "RS256" || c.Use != "sig" || c.Issuer != "https://p.example" {
		t.Errorf("candidate = %+v, want alg, use and issuer carried over", c)
	}
	if _, ok := c.KeyOps["verify"]; !ok || len(c.KeyOps) != 1 {
		t.Errorf("KeyOps = %v, want {verify}", c.KeyOps)
	}
}

// A set with exactly one key and no kid is selectable under the empty kid; any
// other shape with kid-less keys is not.
func TestGetSingleKeyWithoutKidIsAnonymous(t *testing.T) {
	set := get(t, `{"keys":[{"kty":"RSA","n":"`+rsaN+`","e":"AQAB"}]}`)
	if !set.AnonAvailable || len(set.Keys[""]) != 1 {
		t.Fatalf("one key without kid: AnonAvailable = %v, Keys = %v, want it under the empty kid", set.AnonAvailable, set.Keys)
	}

	set = get(t, `{"keys":[{"kty":"RSA","n":"`+rsaN+`","e":"AQAB"},{"kty":"RSA","n":"`+rsaN+`","e":"AQAB"}]}`)
	if set.AnonAvailable || len(set.Keys) != 0 {
		t.Fatalf("two keys without kid: AnonAvailable = %v, Keys = %v, want neither selectable", set.AnonAvailable, set.Keys)
	}

	set = get(t, `{"keys":[{"kty":"RSA","kid":"k","n":"`+rsaN+`","e":"AQAB"},{"kty":"RSA","n":"`+rsaN+`","e":"AQAB"}]}`)
	if set.AnonAvailable || len(set.Keys[""]) != 0 {
		t.Fatalf("a kid-less key beside a named one: AnonAvailable = %v, Keys = %v, want it left out", set.AnonAvailable, set.Keys)
	}
}

// An authoritative empty document is a success carrying no keys.
func TestGetEmptyDocumentIsAnEmptySet(t *testing.T) {
	set := get(t, `{"keys":[]}`)
	if set.AnonAvailable || len(set.Keys) != 0 {
		t.Fatalf("empty document = %+v, want an empty set", set)
	}
}

// A caller that went away says nothing about the provider: its context error
// comes back as is and no attempt is recorded, so the next caller may try at
// once. Every failure that does reflect on the provider is recorded.
func TestGetRecordsAnAttemptOnlyForProviderFailures(t *testing.T) {
	srv := serve(t, `{"keys":[]}`)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	failed := 0
	_, err := Get(ctx, srv.Client(), srv.URL, errFetch, func() { failed++ })
	if !errors.Is(err, context.Canceled) || errors.Is(err, errFetch) {
		t.Fatalf("cancelled caller: err = %v, want the bare context error", err)
	}
	if failed != 0 {
		t.Errorf("a cancelled caller recorded %d attempts, want 0", failed)
	}

	down := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	down.Close()
	_, err = Get(context.Background(), down.Client(), down.URL, errFetch, func() { failed++ })
	if !errors.Is(err, errFetch) {
		t.Fatalf("unreachable provider: err = %v, want errFetch", err)
	}
	if failed != 1 {
		t.Errorf("an unreachable provider recorded %d attempts, want 1", failed)
	}
}
