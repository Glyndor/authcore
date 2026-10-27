package jwks_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/oauth"
	"github.com/Glyndor/authcore/tests/hostile/oauth/hostiletest"
)

// Attacker: someone who can present tokens (any user) or who controls what
// the JWKS endpoint answers (a compromised provider, a man in the middle).
// Effects they want: turn the client into a request amplifier aimed at the
// provider, get a key accepted that the provider did not publish for
// signatures, or have a failure leave behind state that later accepts forgeries.

func TestHostile_JWKS_unknownKidFloodDoesNotAmplifyIntoTheProvider(t *testing.T) {
	a, _ := hostiletest.RSAKeys()
	srv := hostiletest.Serve(t, hostiletest.StaticBody(hostiletest.JWKSDoc(hostiletest.RSAJWK(hostiletest.KID, &a.PublicKey, nil))))
	c := hostiletest.OIDCClient(t, srv.URL, nil)

	for i := range 300 {
		tok := hostiletest.Mint{Key: a, Kid: fmt.Sprintf("random-%d", i), Claims: hostiletest.Claims(hostiletest.Nonce, nil)}.String(t)
		got, err := hostiletest.Verify(t, c, tok)
		hostiletest.MustRejectToken(t, got, err)
	}
	if n := srv.Hits.Load(); n != 1 {
		t.Fatalf("300 tokens with unknown kids caused %d JWKS fetches, want 1", n)
	}
	// The flood did not poison the cache: the real key still verifies.
	if _, err := hostiletest.Verify(t, c, hostiletest.SignA(t, hostiletest.Claims(hostiletest.Nonce, nil))); err != nil {
		t.Fatalf("control: a legitimate token was refused after the flood: %v", err)
	}
}

func TestHostile_JWKS_concurrentUnknownKidFloodCollapsesIntoOneFetch(t *testing.T) {
	a, _ := hostiletest.RSAKeys()
	const n = 64
	// The provider holds its answer until every worker has entered the
	// verification, so the single fetch is still in flight while the burst
	// arrives. The count is the signal: the last worker to arrive releases
	// the provider, so the test does not depend on how long the machine
	// takes to start and schedule 64 goroutines.
	var arrived atomic.Int64
	allIn := make(chan struct{})
	srv := hostiletest.Serve(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-allIn
		_, _ = w.Write(hostiletest.JWKSDoc(hostiletest.RSAJWK(hostiletest.KID, &a.PublicKey, nil)))
	}))
	c := hostiletest.OIDCClient(t, srv.URL, nil)

	tokens := make([]string, n)
	for i := range tokens {
		tokens[i] = hostiletest.Mint{Key: a, Kid: fmt.Sprintf("evil-%d", i), Claims: hostiletest.Claims(hostiletest.Nonce, nil)}.String(t)
	}
	var wg sync.WaitGroup
	var accepted atomic.Int64
	for _, tok := range tokens {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if arrived.Add(1) == n {
				close(allIn)
			}
			if _, err := c.VerifyIDToken(hostiletest.Ctx(t), tok, hostiletest.Nonce); err == nil {
				accepted.Add(1)
			}
		}()
	}
	wg.Wait()
	if accepted.Load() != 0 {
		t.Fatalf("%d forged tokens were accepted", accepted.Load())
	}
	if got := srv.Hits.Load(); got != 1 {
		t.Fatalf("%d concurrent unknown-kid tokens caused %d JWKS fetches, want 1", n, got)
	}
}

func TestHostile_JWKS_aFailingProviderIsNotHammered(t *testing.T) {
	for name, h := range map[string]http.Handler{
		"status 500":                http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "boom", 500) }),
		"status 200 with html":      hostiletest.StaticBody([]byte("<html>captive portal</html>")),
		"status 200 with truncated": hostiletest.StaticBody([]byte(`{"keys":[{"kty":"RSA"`)),
		"status 403":                http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "no", http.StatusForbidden) }),
	} {
		t.Run(name, func(t *testing.T) {
			srv := hostiletest.Serve(t, h)
			c := hostiletest.OIDCClient(t, srv.URL, nil)
			for range 100 {
				got, err := hostiletest.Verify(t, c, hostiletest.SignA(t, hostiletest.Claims(hostiletest.Nonce, nil)))
				hostiletest.MustRejectToken(t, got, err)
				if !errors.Is(err, oauth.ErrJWKS) {
					t.Fatalf("the refusal does not say the keys were unavailable: %v", err)
				}
			}
			if n := srv.Hits.Load(); n != 1 {
				t.Fatalf("100 verifications against a failing provider caused %d fetches, want 1", n)
			}
		})
	}
}

// A failure must not leave a cache that later accepts something it should not,
// and a recovered provider is not trusted retroactively for tokens it never signed.
func TestHostile_JWKS_afterAFailureNothingForgedIsAccepted(t *testing.T) {
	a, b := hostiletest.RSAKeys()
	var fail atomic.Bool
	fail.Store(true)
	srv := hostiletest.Serve(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if fail.Load() {
			http.Error(w, "boom", 500)
			return
		}
		_, _ = w.Write(hostiletest.JWKSDoc(hostiletest.RSAJWK(hostiletest.KID, &a.PublicKey, nil)))
	}))
	c := hostiletest.OIDCClient(t, srv.URL, nil)
	if got, err := hostiletest.Verify(t, c, hostiletest.SignA(t, hostiletest.Claims(hostiletest.Nonce, nil))); err == nil {
		t.Fatalf("accepted during the outage: %+v", got)
	}
	fail.Store(false)
	forged := hostiletest.Mint{Key: b, Claims: hostiletest.Claims(hostiletest.Nonce, nil)}.String(t)
	if got, err := hostiletest.Verify(t, c, forged); err == nil {
		t.Fatalf("a forged token was accepted after the outage: %+v", got)
	}
}

// A hostile rotation: the endpoint starts publishing the attacker's key under
// the kid the client already trusts. The cached key set stays authoritative
// until it expires; the attacker's signature must not verify in the meantime.
func TestHostile_JWKS_rotationToAnAttackerKeyDoesNotRewriteTheCache(t *testing.T) {
	a, b := hostiletest.RSAKeys()
	var swapped atomic.Bool
	srv := hostiletest.Serve(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if swapped.Load() {
			_, _ = w.Write(hostiletest.JWKSDoc(hostiletest.RSAJWK(hostiletest.KID, &b.PublicKey, nil), hostiletest.RSAJWK("attacker", &b.PublicKey, nil)))
			return
		}
		_, _ = w.Write(hostiletest.JWKSDoc(hostiletest.RSAJWK(hostiletest.KID, &a.PublicKey, nil)))
	}))
	c := hostiletest.OIDCClient(t, srv.URL, nil)
	if _, err := hostiletest.Verify(t, c, hostiletest.SignA(t, hostiletest.Claims(hostiletest.Nonce, nil))); err != nil {
		t.Fatalf("control: %v", err)
	}
	swapped.Store(true)
	for name, tok := range map[string]string{
		"attacker key under the trusted kid": hostiletest.Mint{Key: b, Claims: hostiletest.Claims(hostiletest.Nonce, nil)}.String(t),
		"attacker key under its own new kid": hostiletest.Mint{Key: b, Kid: "attacker", Claims: hostiletest.Claims(hostiletest.Nonce, nil)}.String(t),
	} {
		if got, err := hostiletest.Verify(t, c, tok); err == nil {
			t.Fatalf("%s: accepted %+v", name, got)
		}
	}
	if n := srv.Hits.Load(); n != 1 {
		t.Fatalf("the attacker's tokens forced %d JWKS fetches, want 1", n)
	}
	// The trusted key still works: the rotation did not take effect early.
	if _, err := hostiletest.Verify(t, c, hostiletest.SignA(t, hostiletest.Claims(hostiletest.Nonce, nil))); err != nil {
		t.Fatalf("the cached key stopped working: %v", err)
	}
}

// The response cap must hold for the key set: keys beyond it are not read, so
// they cannot be trusted either, and a valid key hidden past the cap is not "found".
func TestHostile_JWKS_keysPastTheSizeCapAreNeverTrusted(t *testing.T) {
	a, _ := hostiletest.RSAKeys()
	junk := `{"kty":"oct","kid":"junk","k":"` + strings.Repeat("A", 1000) + `"}`
	build := func(n int) []byte {
		var sb strings.Builder
		sb.WriteString(`{"keys":[`)
		for range n {
			sb.WriteString(junk)
			sb.WriteString(",")
		}
		sb.Write(mustJSON(hostiletest.RSAJWK(hostiletest.KID, &a.PublicKey, nil)))
		sb.WriteString("]}")
		return []byte(sb.String())
	}
	under := build(900) // about 0.9 MB
	over := build(1100) // about 1.1 MB
	if len(under) >= hostiletest.ResponseCap || len(over) <= hostiletest.ResponseCap {
		t.Fatalf("test sizes are off: %d / %d", len(under), len(over))
	}
	c, _ := hostiletest.JWKSClient(t, under)
	if _, err := hostiletest.Verify(t, c, hostiletest.SignA(t, hostiletest.Claims(hostiletest.Nonce, nil))); err != nil {
		t.Fatalf("control: a key set under the cap was refused: %v", err)
	}
	c, _ = hostiletest.JWKSClient(t, over)
	got, err := hostiletest.Verify(t, c, hostiletest.SignA(t, hostiletest.Claims(hostiletest.Nonce, nil)))
	hostiletest.MustRejectToken(t, got, err)
}

// Verification cost is bounded by the key bounds: a key as large and as
// exotic as the parser allows must not make verification expensive.
func TestHostile_JWKS_extremeButAllowedKeysDoNotMakeVerificationExpensive(t *testing.T) {
	a, _ := hostiletest.RSAKeys()
	// A 16384-bit odd modulus with the widest exponent the parser accepts.
	n := make([]byte, 2048)
	for i := range n {
		n[i] = 0xff
	}
	doc := hostiletest.JWKSDoc(map[string]any{"kty": "RSA", "kid": hostiletest.KID, "n": hostiletest.B64(n), "e": hostiletest.B64([]byte{0x7f, 0xff, 0xff, 0xff})})
	c, _ := hostiletest.JWKSClient(t, doc)
	start := time.Now()
	for range 20 {
		got, err := hostiletest.Verify(t, c, hostiletest.SignA(t, hostiletest.Claims(hostiletest.Nonce, nil)))
		hostiletest.MustRejectToken(t, got, err)
	}
	_ = a
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("20 verifications against the largest allowed key took %v", d)
	}
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
