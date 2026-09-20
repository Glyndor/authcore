package oauth_test

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth"
)

// ---- Google preset accepts both issuer spellings ---------------------------

// TestGooglePreset_acceptsBothIssuerSpellings pins the Google preset's
// IssuerValidator: it must accept the https form and the bare host, and
// nothing else. A regression that drops one spelling fails the first pair; a
// regression that widens the set fails the third.
func TestGooglePreset_acceptsBothIssuerSpellings(t *testing.T) {
	p := oauth.Google()
	if p.IssuerValidator == nil {
		t.Fatal("Google preset must wire an IssuerValidator")
	}
	for _, iss := range []string{
		"https://accounts.google.com",
		"accounts.google.com",
	} {
		if !p.IssuerValidator(iss) {
			t.Errorf("Google preset must accept issuer %q", iss)
		}
	}
	for _, iss := range []string{
		"https://accounts.google.com/", // trailing slash
		"http://accounts.google.com",
		"accounts.google.com.evil.example",
		"https://evil.example",
	} {
		if p.IssuerValidator(iss) {
			t.Errorf("Google preset must reject issuer %q", iss)
		}
	}
}

// TestGooglePreset_acceptsTheBareHostIDToken exercises the end-to-end path:
// sign an ID token with iss="accounts.google.com", verify it against a
// provider configured via oauth.Google(), and check the verifier approves.
// Without the IssuerValidator on the preset, this would fail on the exact
// issuer match.
func TestGooglePreset_acceptsTheBareHostIDToken(t *testing.T) {
	key := mustRSA(t)
	n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())
	doc := fmt.Sprintf(`{"keys":[{"kty":"RSA","kid":%q,"n":%q,"e":%q}]}`, testKID, n, e)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(doc))
	}))
	defer srv.Close()

	cfg := oauth.Google()
	cfg.AuthURL = srv.URL + "/a"
	cfg.TokenURL = srv.URL + "/token"
	cfg.JWKSURL = srv.URL
	c, err := oauth.New(fakeProvider{}, oauth.Config{
		ClientID:    testClientID,
		RedirectURL: "https://app.example/cb",
		Provider:    cfg,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	signed := signIDToken(t, key, testKID, validClaims("accounts.google.com", "n"))
	if _, err := c.VerifyIDToken(context.Background(), signed, "n"); err != nil {
		t.Errorf("bare-host issuer must verify, got %v", err)
	}
}

// ---- Microsoft preset rejects a non-GUID tenant with a GUID-named error ----

// TestMicrosoftPreset_rejectsDomainWithGUIDMessage pins the preset's GUID
// requirement and the error message that names it. The brief said "say so in
// the comment and in the error a domain produces", so the message is part of
// the contract — a regression that removes the word "GUID" fails the test.
func TestMicrosoftPreset_rejectsDomainWithGUIDMessage(t *testing.T) {
	for _, tenant := range []string{
		"contoso.onmicrosoft.com",
		"common",
		"",
		"not-a-guid",
	} {
		_, err := oauth.Microsoft(tenant)
		if err == nil {
			t.Errorf("Microsoft(%q) must be refused", tenant)
			continue
		}
		if !strings.Contains(err.Error(), "GUID") {
			t.Errorf("Microsoft(%q) refusal must name the GUID requirement, got %v", tenant, err)
		}
	}
}

// ---- Exchange uses the client auth method the provider advertises ----------

// TestExchange_sendsBasicAuthHeaderWhenAdvertised pins the path where
// discovery advertises "client_secret_basic" and Exchange sends the secret in
// the Authorization header. The provider's recorded credentials and the body
// (which is asserted to carry no client_secret) prove the channel.
func TestExchange_sendsBasicAuthHeaderWhenAdvertised(t *testing.T) {
	const (
		clientID     = "cid-basic"
		clientSecret = "shh-basic"
	)
	var sawAuth string
	var sawForm url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		_ = r.ParseForm()
		sawForm = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":"Bearer","id_token":"idt"}`))
	}))
	defer srv.Close()

	c, err := oauth.New(fakeProvider{}, oauth.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  "https://app.example/cb",
		Scopes:       []string{"openid"},
		Provider: oauth.Provider{
			AuthURL:     srv.URL + "/a",
			TokenURL:    srv.URL,
			JWKSURL:     srv.URL,
			Issuer:      srv.URL,
			AuthMethods: []string{"client_secret_basic"},
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := c.Exchange(context.Background(), "code", "verifier"); err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(clientID+":"+clientSecret))
	if sawAuth != wantAuth {
		t.Errorf("Authorization header = %q, want %q", sawAuth, wantAuth)
	}
	if c := sawForm.Get("client_secret"); c != "" {
		t.Errorf("client_secret must not appear in the body, got %q", c)
	}
}

// TestExchange_keepsPostWhenNothingAdvertised pins the compatibility rule: a
// provider that advertises no authentication method tells us nothing, so
// Exchange keeps sending the secret in the body, which is what this library
// sent before it could choose. Switching such a provider to Basic would break
// every hand-configured token endpoint that only accepts Post.
func TestExchange_keepsPostWhenNothingAdvertised(t *testing.T) {
	const (
		clientID     = "cid-default"
		clientSecret = "shh-default"
	)
	var sawAuth string
	var sawForm url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		_ = r.ParseForm()
		sawForm = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":"Bearer","id_token":"idt"}`))
	}))
	defer srv.Close()

	c, err := oauth.New(fakeProvider{}, oauth.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  "https://app.example/cb",
		Scopes:       []string{"openid"},
		Provider: oauth.Provider{
			AuthURL:  srv.URL + "/a",
			TokenURL: srv.URL,
			JWKSURL:  srv.URL,
			Issuer:   srv.URL,
			// AuthMethods intentionally absent: OIDC default applies.
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := c.Exchange(context.Background(), "code", "verifier"); err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if sawAuth != "" {
		t.Errorf("no method advertised: the secret must stay in the body, got Authorization %q", sawAuth)
	}
	if got := sawForm.Get("client_secret"); got != clientSecret {
		t.Errorf("client_secret in body = %q, want the configured secret", got)
	}
}

// TestExchange_sendsPostOnlyWhenBasicIsNotAdvertised pins the path where the
// provider advertises only "client_secret_post": Exchange sends it in the body,
// and the Authorization header is empty.
func TestExchange_sendsPostOnlyWhenBasicIsNotAdvertised(t *testing.T) {
	const (
		clientID     = "cid-post"
		clientSecret = "shh-post"
	)
	var sawAuth string
	var sawForm url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		_ = r.ParseForm()
		sawForm = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":"Bearer","id_token":"idt"}`))
	}))
	defer srv.Close()

	c, err := oauth.New(fakeProvider{}, oauth.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  "https://app.example/cb",
		Scopes:       []string{"openid"},
		Provider: oauth.Provider{
			AuthURL:     srv.URL + "/a",
			TokenURL:    srv.URL,
			JWKSURL:     srv.URL,
			Issuer:      srv.URL,
			AuthMethods: []string{"client_secret_post"},
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := c.Exchange(context.Background(), "code", "verifier"); err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if sawAuth != "" {
		t.Errorf("Authorization header must be empty under Post, got %q", sawAuth)
	}
	if got, want := sawForm.Get("client_secret"), clientSecret; got != want {
		t.Errorf("client_secret in body = %q, want %q", got, want)
	}
}

// TestExchange_refusesUnsupplicableAuthMethod pins the path where the
// provider advertises only methods the library does not implement (e.g.
// "private_key_jwt"). Exchange must fail before any request leaves the
// machine, so the client secret is never sent on an unrecognised channel.
func TestExchange_refusesUnsupplicableAuthMethod(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":"Bearer","id_token":"idt"}`))
	}))
	defer srv.Close()

	c, err := oauth.New(fakeProvider{}, oauth.Config{
		ClientID:     "cid-jwk",
		ClientSecret: "shh-jwk",
		RedirectURL:  "https://app.example/cb",
		Scopes:       []string{"openid"},
		Provider: oauth.Provider{
			AuthURL:     srv.URL + "/a",
			TokenURL:    srv.URL,
			JWKSURL:     srv.URL,
			Issuer:      srv.URL,
			AuthMethods: []string{"private_key_jwt"},
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	var exchangeErr error
	if _, exchangeErr = c.Exchange(context.Background(), "code", "verifier"); exchangeErr == nil {
		t.Fatal("Exchange must refuse when only unsupported methods are advertised")
	}
	if !strings.Contains(exchangeErr.Error(), "supported") {
		t.Errorf("refusal must name the missing support, got %v", exchangeErr)
	}
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Errorf("token endpoint was hit %d times; an unsupplicable auth method must short-circuit", got)
	}
}

// ---- URL validation: opaque, empty host, fragment ---------------------------

// TestNew_rejectsOpaqueHTTPSEndpoint requires the validation to refuse
// https:opaque and https:///path. The brief lists these as inputs that
// previously slipped through validation and only failed later, when the fetch
// ran.
func TestNew_rejectsOpaqueHTTPSEndpoint(t *testing.T) {
	for name, raw := range map[string]string{
		"opaque":       "https:opaque",
		"empty host":   "https:///token",
		"opaque query": "https:?x=y",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := oauth.New(fakeProvider{}, oauth.Config{
				ClientID:    "x",
				RedirectURL: "https://app.example/cb",
				Provider: oauth.Provider{
					Issuer:   "https://id.example",
					AuthURL:  "https://id.example/auth",
					TokenURL: raw,
					JWKSURL:  "https://id.example/jwks",
				},
			})
			if err == nil {
				t.Fatalf("URL %q must be rejected", raw)
			}
			if !errors.Is(err, oauth.ErrInvalidConfig) {
				t.Fatalf("rejection must wrap ErrInvalidConfig, got %v", err)
			}
			if !strings.Contains(err.Error(), "hierarchical") && !strings.Contains(err.Error(), "host") {
				t.Fatalf("rejection must name the rule (hierarchical/host), got %v", err)
			}
		})
	}
}

// TestNew_rejectsFragmentOnAuthURL pins the new fragment check. A fragment
// in the AuthURL would land every appended parameter inside the fragment,
// where no OIDC server reads them. Refuse it at validation.
func TestNew_rejectsFragmentOnAuthURL(t *testing.T) {
	_, err := oauth.New(fakeProvider{}, oauth.Config{
		ClientID:    "x",
		RedirectURL: "https://app.example/cb",
		Provider: oauth.Provider{
			AuthURL:  "https://id.example/auth#frag",
			TokenURL: "https://id.example/token",
			JWKSURL:  "https://id.example/jwks",
			Issuer:   "https://id.example",
		},
	})
	if err == nil {
		t.Fatal("an AuthURL with a fragment must be rejected")
	}
	if !strings.Contains(err.Error(), "fragment") {
		t.Fatalf("rejection must name the fragment rule, got %v", err)
	}
}

// TestNew_acceptsFragmentFreeAuthURL is the acceptance pair for the
// fragment rule.
func TestNew_acceptsFragmentFreeAuthURL(t *testing.T) {
	if _, err := oauth.New(fakeProvider{}, oauth.Config{
		ClientID:    "x",
		RedirectURL: "https://app.example/cb",
		Provider: oauth.Provider{
			AuthURL:  "https://id.example/auth",
			TokenURL: "https://id.example/token",
			JWKSURL:  "https://id.example/jwks",
			Issuer:   "https://id.example",
		},
	}); err != nil {
		t.Fatalf("a fragment-free AuthURL must construct, got %v", err)
	}
}

// ---- AuthCodeURL: parameter merging and dedup --------------------------------

// TestAuthCodeURL_dedupsPreExistingQueryParameters pins the parse-then-Set
// path: when the AuthURL already carries a "state" or "code_challenge"
// parameter, the call must overwrite it instead of producing duplicates
// (which most OIDC servers read as the pre-existing value).
func TestAuthCodeURL_dedupsPreExistingQueryParameters(t *testing.T) {
	c, err := oauth.New(fakeProvider{}, oauth.Config{
		ClientID:    testClientID,
		RedirectURL: "https://app.example/cb",
		Provider: oauth.Provider{
			Issuer:   "https://id.example",
			AuthURL:  "https://id.example/auth?state=fixed&client_id=cid&code_challenge=pre-existing",
			TokenURL: "https://id.example/token",
			JWKSURL:  "https://id.example/jwks",
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req, err := c.AuthCodeURL()
	if err != nil {
		t.Fatalf("AuthCodeURL: %v", err)
	}
	u, err := url.Parse(req.URL)
	if err != nil {
		t.Fatalf("parse AuthCodeURL result: %v", err)
	}
	if got := u.Query().Get("state"); got != req.State {
		t.Errorf("state = %q, want the fresh value %q", got, req.State)
	}
	if got := u.Query().Get("code_challenge"); got == "pre-existing" {
		t.Errorf("code_challenge must be overwritten, still %q", got)
	}
	if got := u.Query().Get("client_id"); got != testClientID {
		t.Errorf("client_id = %q, want %q", got, testClientID)
	}
}

// TestAuthCodeURL_handlesQuerylessAuthURL pins the parse path for a URL
// with no pre-existing query string.
func TestAuthCodeURL_handlesQuerylessAuthURL(t *testing.T) {
	c, _ := oauth.New(fakeProvider{}, oauth.Config{
		ClientID:    testClientID,
		RedirectURL: "https://app.example/cb",
		Provider: oauth.Provider{
			Issuer:   "https://id.example",
			AuthURL:  "https://id.example/auth",
			TokenURL: "https://id.example/token",
			JWKSURL:  "https://id.example/jwks",
		},
	})
	req, err := c.AuthCodeURL()
	if err != nil {
		t.Fatalf("AuthCodeURL: %v", err)
	}
	if !strings.HasPrefix(req.URL, "https://id.example/auth?") {
		t.Errorf("AuthCodeURL result = %q, want a path followed by ?", req.URL)
	}
}

// ---- supplied HTTPClient: zero timeout gets the library default ------------

// TestSuppliedClient_zeroTimeoutGetsTheLibraryDefault pins the public-facing
// half of the rule: a caller-supplied client with a zero Timeout is accepted
// at construction and the caller's value is preserved on the original. The
// library's internal copy carries the 10-second default; that branch is
// pinned by TestGuardClient_appliesDefaultTimeoutToZeroTimeoutCaller in the
// internal test, since the internal http.Client is not exposed here.
func TestSuppliedClient_zeroTimeoutGetsTheLibraryDefault(t *testing.T) {
	caller := &http.Client{} // Timeout deliberately zero
	if _, err := oauth.New(fakeProvider{}, oauth.Config{
		ClientID:    testClientID,
		RedirectURL: "https://app.example/cb",
		HTTPClient:  caller,
		Provider:    oauth.Google(),
	}); err != nil {
		t.Fatalf("New: %v", err)
	}
	if caller.Timeout != 0 {
		t.Errorf("the caller's client was mutated: Timeout = %v", caller.Timeout)
	}
}

// ---- Discovery: trailing-slash issuer rejected (exact match only) ----------

// TestDiscover_rejectsTrailingSlashIssuer pins the exact-match rule: the
// trimmed form used to be accepted because it was used to build the well-known
// URL. A document that returns the trimmed form is rejected — it does not
// match the issuer the caller asked for byte-for-byte.
func TestDiscover_rejectsTrailingSlashIssuer(t *testing.T) {
	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration") {
			http.NotFound(w, r)
			return
		}
		fmt.Fprintf(w, `{
			"issuer": %q,
			"authorization_endpoint": %q,
			"token_endpoint": %q,
			"jwks_uri": %q
		}`, srvURL, srvURL+"/a", srvURL+"/t", srvURL+"/j")
	}))
	srvURL = srv.URL
	defer srv.Close()
	// Caller asks for "https://id.example/" (trailing slash); document
	// returns the bare form. The OIDC requirement is exact match.
	if _, err := oauth.Discover(context.Background(), srv.URL+"/", nil); err == nil {
		t.Error("Discover must reject the trimmed form when the caller asked with a trailing slash")
	}
}
