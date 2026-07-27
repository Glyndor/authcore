package oauth_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

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

func TestExchange_refusesUnsafeRedirect(t *testing.T) {
	for name, loc := range map[string]string{
		"cross-origin (leaks the secret)": "https://evil.example/steal",
		"private metadata host (SSRF)":    "https://169.254.169.254/latest",
		"plaintext downgrade":             "http://127.0.0.1/x",
	} {
		t.Run(name, func(t *testing.T) {
			c := tokenServerRedirectingTo(t, loc)
			if _, err := c.Exchange(context.Background(), "code", "verifier"); err == nil {
				t.Errorf("token exchange must refuse the redirect to %q", loc)
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
	if _, err := c.VerifyIDToken(context.Background(), strings.Repeat("a", 20000), "n"); err == nil {
		t.Error("an oversized id token must be rejected before parsing")
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
	xB64 := x

	cases := map[string]string{
		"off-curve point":   fmt.Sprintf(`{"keys":[{"kty":"EC","kid":%q,"crv":"P-256","x":%q,"y":%q}]}`, testKID, xB64, base64.RawURLEncoding.EncodeToString(yBad)),
		"unsupported curve": fmt.Sprintf(`{"keys":[{"kty":"EC","kid":%q,"crv":"P-999","x":%q,"y":%q}]}`, testKID, xB64, base64.RawURLEncoding.EncodeToString(yGood)),
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(doc))
			}))
			defer srv.Close()
			c := newClient(t, srv)
			tok := signIDToken(t, signKey, testKID, validClaims(srv.URL, "n"))
			if _, err := c.VerifyIDToken(context.Background(), tok, "n"); err == nil {
				t.Errorf("%s: invalid EC key must be rejected", name)
			}
		})
	}
}

func TestVerifyIDToken_rsaBoundsRejected(t *testing.T) {
	key := mustRSA(t)
	goodN := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
	hugeN := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xff}, 2049)) // ~16392 bits, over the cap
	wideE := base64.RawURLEncoding.EncodeToString([]byte{0x01, 0, 0, 0, 0x03})      // 33-bit exponent

	cases := map[string]string{
		"oversized modulus": fmt.Sprintf(`{"keys":[{"kty":"RSA","kid":%q,"n":%q,"e":"AQAB"}]}`, testKID, hugeN),
		"wide exponent":     fmt.Sprintf(`{"keys":[{"kty":"RSA","kid":%q,"n":%q,"e":%q}]}`, testKID, goodN, wideE),
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(doc))
			}))
			defer srv.Close()
			c := newClient(t, srv)
			tok := signIDToken(t, key, testKID, validClaims(srv.URL, "n"))
			if _, err := c.VerifyIDToken(context.Background(), tok, "n"); err == nil {
				t.Errorf("%s: out-of-range RSA key must be rejected", name)
			}
		})
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
