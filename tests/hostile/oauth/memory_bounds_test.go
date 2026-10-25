package hostile_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// Attacker: a provider (or anything answering for one) that sends the largest
// body the client will read, in the shape that costs the most to decode. The
// caps bound what is read; these tests bound what reading it costs, as a
// multiple of the body, and what stays behind. The multiples are the ones
// measured on 2026-10-25 with headroom, so they catch a regression to
// something worse, not noise: a client that suddenly needs 500 times its
// input is a different client.

// allocOf reports what f allocated: bytes and allocation count.
func allocOf(f func()) (bytes, mallocs uint64) {
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc, after.Mallocs - before.Mallocs
}

func heapInUse() uint64 {
	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

// ecKeys returns n distinct-kid EC keys, all with the same public point (the
// parse cost is what matters, not the keys).
func ecKeys(n int) []map[string]any {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	out := make([]map[string]any, n)
	for i := range out {
		out[i] = ecJWK(fmt.Sprintf("k%06d", i), "P-256", &k.PublicKey, nil)
	}
	return out
}

func TestHostile_Memory_theLargestAllowedResponsesCostABoundedMultipleOfTheirSize(t *testing.T) {
	a, _ := rsaKeys()
	const mib = 1 << 20
	fullJWKS := jwksDoc(ecKeys(7300)...) // about 1 MiB of keys the client can parse
	junkJWKS := []byte(`{"keys":[` + strings.Repeat(`{"kty":"oct","k":"AAAA"},`, mib/26-2) + `{"kty":"oct"}]}`)
	longString := []byte(`{"id":1,"x":"` + strings.Repeat("a", mib-100) + `"}`)
	numberArray := []byte(`{"id":1,"x":[` + strings.Repeat("1,", mib/2-20) + `1]}`)
	bigToken := tokenBody(map[string]string{"access_token": strings.Repeat("a", mib-200), "token_type": "Bearer", "id_token": "x"})
	tok := mint{Key: a, Kid: "k000010", Claims: claims(testNonce, nil)}.String(t)

	cases := []struct {
		name   string
		body   []byte
		factor uint64 // measured multiple of the body, rounded up with headroom
		run    func(srvURL string)
	}{
		{"a JWKS full of usable keys", fullJWKS, 25, func(u string) { _, _ = verify(t, oidcClient(t, u, nil), tok) }},
		{"a JWKS full of unusable keys", junkJWKS, 80, func(u string) { _, _ = verify(t, oidcClient(t, u, nil), tok) }},
		{"a token response with a huge token", bigToken, 10, func(u string) { _, _ = tokenClient(t, u, nil).Exchange(ctx(t), "c", "v") }},
		{"a profile that is one long string", longString, 20, func(u string) { _, _ = userinfoClient(t, u, nil).UserInfo(ctx(t), "at") }},
		{"a profile that is half a million numbers", numberArray, 100, func(u string) { _, _ = userinfoClient(t, u, nil).UserInfo(ctx(t), "at") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := serve(t, staticBody(tc.body))
			got, _ := allocOf(func() { tc.run(srv.URL) })
			if limit := uint64(len(tc.body)) * tc.factor; got > limit {
				t.Fatalf("one call allocated %d bytes for a %d-byte body (%.0fx), over the %dx bound", got, len(tc.body), float64(got)/float64(len(tc.body)), tc.factor)
			}
		})
	}
}

// What the cache keeps after a refresh is the parsed keys, not the document.
func TestHostile_Memory_aMaximalKeySetRetainsABoundedMultipleOfItself(t *testing.T) {
	a, _ := rsaKeys()
	doc := jwksDoc(ecKeys(7300)...)
	srv := serve(t, staticBody(doc))
	before := heapInUse()
	c := oidcClient(t, srv.URL, nil)
	_, _ = verify(t, c, mint{Key: a, Kid: "k000010", Claims: claims(testNonce, nil)}.String(t))
	retained := int64(heapInUse()) - int64(before)
	runtime.KeepAlive(c)
	if limit := int64(len(doc)) * 6; retained > limit {
		t.Fatalf("a %d-byte key set left %d bytes on the heap, over %d (measured 3x)", len(doc), retained, limit)
	}
}

// A token with an unknown kid is refused without being remembered: the cache
// holds the provider's keys and nothing the caller invented.
func TestHostile_Memory_unknownKidsAreNotRemembered(t *testing.T) {
	c, _ := jwksClient(t, stdJWKS(t))
	forged := func(i int) string {
		hdr := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"alg":"RS256","typ":"JWT","kid":"ghost-%d-%s"}`, i, strings.Repeat("g", 200))))
		body := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"` + testIssuer + `"}`))
		return hdr + "." + body + ".AAAA" // the signature is never reached: the key is
	}
	if _, err := verify(t, c, forged(0)); err == nil { // the first one pays for the refresh
		t.Fatal("control: a forged token verified")
	}
	before := heapInUse()
	for i := 1; i <= 15000; i++ {
		if _, err := c.VerifyIDToken(context.Background(), forged(i), testNonce); err == nil {
			t.Fatal("a forged token verified")
		}
	}
	grown := int64(heapInUse()) - int64(before)
	runtime.KeepAlive(c) // without it the client, and the cache under test, is collected before the heap is read
	if grown > 1<<20 {
		t.Fatalf("15000 unknown kids of ~220 bytes left %d bytes behind; the cache is keeping what it was shown", grown)
	}
}

func TestHostile_Memory_buildingTheAuthorizationRequestStaysSmall(t *testing.T) {
	c := oidcClient(t, "https://idp.example/jwks", nil)
	if allocs := testing.AllocsPerRun(200, func() { _, _ = c.AuthCodeURL() }); allocs > 70 {
		t.Fatalf("AuthCodeURL makes %.0f allocations per call (measured 35)", allocs)
	}
}
