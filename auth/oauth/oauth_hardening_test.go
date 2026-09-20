package oauth_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/oauth"
)

// tokenServerRedirectingTo returns a token endpoint that 307-redirects to loc.
func tokenServerRedirectingTo(t *testing.T, loc string) *oauth.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, loc, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(srv.Close)
	c, err := oauth.New(fakeProvider{}, oauth.Config{
		ClientID:    testClientID,
		RedirectURL: "https://app.example/cb",
		Scopes:      []string{"read:user"},
		Provider:    oauth.Provider{AuthURL: srv.URL + "/a", TokenURL: srv.URL + "/token", UserInfoURL: srv.URL + "/u"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

// TestExchange_refusesUnsafeRedirect requires the redirect policy to refuse a
// token-endpoint redirect that would replay the client secret. The cross-origin
// case points at a local HTTPS server whose URL is rewritten to use the
// "localhost" hostname (a hostname, not an IP literal, so the private-host
// check lets the request through to the cross-origin check). The destination
// handler returns a valid tokens response; if the redirect policy fires,
// Exchange fails; if it does not, Exchange succeeds and the test fails because
// no error was returned. The other cases use URLs that fail at the policy
// stage before any dial. A DNS or dial error used to satisfy the assertion
// without the redirect policy firing.
func TestExchange_refusesUnsafeRedirect(t *testing.T) {
	// destination serves a valid tokens body. The library's http.Client is
	// configured to skip TLS hostname verification (test only) so a removed
	// redirect policy would actually reach the destination, where the
	// handler returns a valid tokens response and Exchange succeeds.
	destination := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":"Bearer"}`))
	}))
	defer destination.Close()

	trustedClient := destination.Client()
	trustedClient.Timeout = 5 * time.Second
	// InsecureSkipVerify is a test-only setting: the destination's cert is
	// for "127.0.0.1" but the redirect URL rewrites the host to "localhost",
	// which the runtime TLS stack would otherwise reject. Production code
	// never runs with this setting.
	if tr, ok := trustedClient.Transport.(*http.Transport); ok {
		if tr.TLSClientConfig == nil {
			tr.TLSClientConfig = &tls.Config{}
		}
		tr.TLSClientConfig.InsecureSkipVerify = true
	}

	// destinationURL rewrites the host to "localhost" so the policy reaches
	// the cross-origin check. The redirect fires before the dial, so TLS
	// verification is the destination's concern, not the policy's.
	destinationURL := strings.Replace(destination.URL, "127.0.0.1", "localhost", 1)

	for name, target := range map[string]string{
		"cross-origin (leaks the secret)": destinationURL,
		"private metadata host (SSRF)":    "https://169.254.169.254/latest",
		"plaintext downgrade":             "http://127.0.0.1/x",
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, target, http.StatusTemporaryRedirect)
			}))
			t.Cleanup(srv.Close)
			c, err := oauth.New(fakeProvider{}, oauth.Config{
				ClientID:    testClientID,
				RedirectURL: "https://app.example/cb",
				Scopes:      []string{"read:user"},
				HTTPClient:  trustedClient,
				Provider: oauth.Provider{
					AuthURL:     srv.URL + "/a",
					TokenURL:    srv.URL + "/token",
					UserInfoURL: srv.URL + "/u",
				},
			})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if _, err := c.Exchange(context.Background(), "code", "verifier"); err == nil {
				t.Errorf("token exchange must refuse the redirect to %q", target)
			}
		})
	}
}

func TestJWKS_concurrentUnknownKidsCollapse(t *testing.T) {
	key := mustRSA(t)
	n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())
	doc := fmt.Sprintf(`{"keys":[{"kty":"RSA","kid":%q,"n":%q,"e":%q}]}`, testKID, n, e)

	var fetches int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&fetches, 1)
		_, _ = w.Write([]byte(doc))
	}))
	defer srv.Close()
	c := newClient(t, srv)

	// A burst of tokens with distinct unknown kids must not fan out to one
	// outbound JWKS fetch each — singleflight + the throttle collapse them.
	var wg sync.WaitGroup
	for i := 0; i < 25; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tok := signIDToken(t, key, fmt.Sprintf("bogus-%d", i), validClaims(srv.URL, "n"))
			_, _ = c.VerifyIDToken(context.Background(), tok, "n")
		}(i)
	}
	wg.Wait()
	if got := atomic.LoadInt32(&fetches); got > 3 {
		t.Errorf("burst of unknown kids caused %d JWKS fetches, want few", got)
	}
}

func TestVerifyIDToken_oversizedRejected(t *testing.T) {
	key := mustRSA(t)
	srv := jwksServer(t, &key.PublicKey)
	defer srv.Close()
	c := newClient(t, srv)
	// A well-formed but oversized token: signed correctly against the key the
	// JWKS advertises, with a large custom claim that pushes the encoded form
	// past the size guard. A run of raw bytes would be refused by the JWT
	// parser before the size guard, and the test would pass for the wrong
	// reason.
	cl := validClaims(srv.URL, "n")
	cl["junk"] = strings.Repeat("a", 20000)
	tok := signIDToken(t, key, testKID, cl)
	if _, err := c.VerifyIDToken(context.Background(), tok, "n"); err == nil {
		t.Error("an oversized id token must be rejected before parsing")
	} else if !strings.Contains(err.Error(), "too large") {
		t.Fatalf("refusal must name the size guard, got %v", err)
	}
}

func TestVerifyIDToken_issuerValidatorMultiTenant(t *testing.T) {
	key := mustRSA(t)
	srv := jwksServer(t, &key.PublicKey)
	defer srv.Close()

	tenantIss := "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0"
	mk := func(validator func(string) bool) *oauth.Client {
		c, err := oauth.New(fakeProvider{}, oauth.Config{
			ClientID:    testClientID,
			RedirectURL: "https://app.example/cb",
			Provider: oauth.Provider{
				AuthURL: srv.URL + "/a", TokenURL: srv.URL + "/t", JWKSURL: srv.URL,
				// no fixed Issuer — the validator handles it
			},
			IssuerValidator: validator,
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		return c
	}

	// A token whose dynamic per-tenant issuer the validator approves verifies,
	// even though no fixed Provider.Issuer matches it.
	tok := signIDToken(t, key, testKID, validClaims(tenantIss, "n"))
	ok := mk(func(iss string) bool { return iss == tenantIss })
	if _, err := ok.VerifyIDToken(context.Background(), tok, "n"); err != nil {
		t.Errorf("validator-approved issuer should verify, got %v", err)
	}

	// A validator that rejects the issuer fails closed.
	reject := mk(func(string) bool { return false })
	if _, err := reject.VerifyIDToken(context.Background(), tok, "n"); err == nil {
		t.Error("validator-rejected issuer must be refused")
	}
}

func TestAzureMultiTenantIssuer(t *testing.T) {
	accept := oauth.AzureMultiTenantIssuer()
	good := "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0"
	if !accept(good) {
		t.Errorf("expected %q to be accepted", good)
	}
	for _, bad := range []string{
		"https://accounts.google.com",
		"https://login.microsoftonline.com/common/v2.0",
		"https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v1.0",
		"http://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0",
	} {
		if accept(bad) {
			t.Errorf("expected %q to be rejected", bad)
		}
	}
}

func TestVerifyIDToken_ecOffCurveAndBadCurveRejected(t *testing.T) {
	signKey := mustRSA(t)
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ec: %v", err)
	}
	raw, err := ec.PublicKey.Bytes()
	if err != nil {
		t.Fatalf("ec bytes: %v", err)
	}
	x := base64.RawURLEncoding.EncodeToString(raw[1:33])
	yGood := raw[33:65]
	yBad := append([]byte(nil), yGood...)
	yBad[len(yBad)-1] ^= 0xff // perturb y so the point is no longer on the curve

	// The end-to-end test only proves the verifier refuses to verify: an
	// off-curve point in the JWKS would be rejected because no key is found
	// for the kid, not because the on-curve check fired. The parser-level
	// test for the same input lives in jwks_bounds_internal_test.go and
	// pins the rejection text.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(fmt.Sprintf(`{"keys":[{"kty":"EC","kid":%q,"crv":"P-256","x":%q,"y":%q}]}`, testKID, x, base64.RawURLEncoding.EncodeToString(yBad))))
	}))
	defer srv.Close()
	c := newClient(t, srv)
	tok := signIDToken(t, signKey, testKID, validClaims(srv.URL, "n"))
	if _, err := c.VerifyIDToken(context.Background(), tok, "n"); err == nil {
		t.Error("off-curve point must be rejected by the verifier")
	}
}

func TestVerifyIDToken_rsaBoundsRejected(t *testing.T) {
	// The end-to-end test only proves the verifier refuses to verify: an
	// oversized modulus or a wide exponent would be rejected because no key
	// is found for the kid (or because signature verification fails), not
	// because the bounds check fired. The parser-level tests for the same
	// inputs live in jwks_bounds_internal_test.go and pin each bound by
	// name.
	key := mustRSA(t)
	doc := fmt.Sprintf(`{"keys":[{"kty":"RSA","kid":%q,"n":%q,"e":"AQAB"}]}`,
		testKID, base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xff}, 2049)))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(doc))
	}))
	defer srv.Close()
	c := newClient(t, srv)
	tok := signIDToken(t, key, testKID, validClaims(srv.URL, "n"))
	if _, err := c.VerifyIDToken(context.Background(), tok, "n"); err == nil {
		t.Error("out-of-range RSA key must be rejected by the verifier")
	}
}

// ---- HTTPS enforcement ------------------------------------------------------

func TestNew_rejectsNonHTTPSEndpoint(t *testing.T) {
	_, err := oauth.New(fakeProvider{}, oauth.Config{
		ClientID:    "x",
		RedirectURL: "https://app.example/cb",
		Provider: oauth.Provider{
			Issuer:   "https://id.example",
			AuthURL:  "http://id.example/auth", // plaintext — must be rejected
			TokenURL: "https://id.example/token",
			JWKSURL:  "https://id.example/jwks",
		},
	})
	if err == nil {
		t.Error("expected a non-https endpoint to be rejected")
	}
}

func TestNew_allowsLoopbackHTTP(t *testing.T) {
	_, err := oauth.New(fakeProvider{}, oauth.Config{
		ClientID:    "x",
		RedirectURL: "http://localhost:8080/cb",
		Provider: oauth.Provider{
			AuthURL:     "http://127.0.0.1:9000/auth",
			TokenURL:    "http://127.0.0.1:9000/token",
			UserInfoURL: "http://127.0.0.1:9000/userinfo",
		},
	})
	if err != nil {
		t.Errorf("loopback http should be allowed for local dev, got %v", err)
	}
}

func TestDiscover_rejectsNonHTTPSIssuer(t *testing.T) {
	if _, err := oauth.Discover(context.Background(), "http://id.example", nil); err == nil {
		t.Error("expected a non-https issuer to be rejected before any fetch")
	}
}

// ---- OAuth2 Exchange no longer requires an id_token -------------------------

func TestExchange_oauth2ReturnsTokensWithoutIDToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// A plain-OAuth2 provider returns no id_token.
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":"bearer"}`))
	}))
	defer srv.Close()

	c, err := oauth.New(fakeProvider{}, oauth.Config{
		ClientID:    testClientID,
		RedirectURL: "https://app.example/cb",
		Scopes:      []string{"read:user"},
		Provider: oauth.Provider{
			AuthURL:     srv.URL + "/auth",
			TokenURL:    srv.URL + "/token",
			UserInfoURL: srv.URL + "/userinfo",
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	tok, err := c.Exchange(context.Background(), "code", "verifier")
	if err != nil {
		t.Fatalf("OAuth2 exchange must succeed without an id_token, got %v", err)
	}
	if tok.AccessToken != "at" {
		t.Errorf("access token = %q, want at", tok.AccessToken)
	}
}

// ---- JWKS: encryption keys are not used for signature verification ----------

func TestVerifyIDToken_encUseKeySkipped(t *testing.T) {
	key := mustRSA(t)
	n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())
	// The only key carries use:"enc" — it must not be selected to verify a signature.
	doc := fmt.Sprintf(`{"keys":[{"kty":"RSA","kid":%q,"use":"enc","n":%q,"e":%q}]}`, testKID, n, e)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(doc))
	}))
	defer srv.Close()
	c := newClient(t, srv)

	tok := signIDToken(t, key, testKID, validClaims(srv.URL, "n"))
	if _, err := c.VerifyIDToken(context.Background(), tok, "n"); err == nil {
		t.Error("an enc-use key must not verify a token signature")
	}
}

// An ID token with no "sub" identifies nobody. Accepting one hands the consumer
// an empty subject, which their storage layer is liable to treat as a real
// account key. The guard that rejects it survived being deleted with the suite
// green — every other test signs a token that has a subject.
func TestVerifyIDToken_rejectsATokenWithNoSubject(t *testing.T) {
	key := mustRSA(t)
	srv := jwksServer(t, &key.PublicKey)
	c := newClient(t, srv)

	claims := validClaims(srv.URL, "n")
	delete(claims, "sub")
	tok := signIDToken(t, key, testKID, claims)

	_, err := c.VerifyIDToken(context.Background(), tok, "n")
	if err == nil {
		t.Fatal("an ID token without a subject must be refused")
	}
	if !strings.Contains(err.Error(), "subject") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
}
