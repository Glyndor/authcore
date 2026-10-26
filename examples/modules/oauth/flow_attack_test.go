package main

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// plainHandler returns the example's handler over a fake plain-OAuth2 provider.
func plainHandler(t *testing.T, crossSite bool) (http.Handler, *fakeProvider) {
	t.Helper()
	p := newFakeProvider(t)
	return newHandler(p.client(t, false), false, crossSite), p
}

func callbackTarget(state, code string) string {
	return "/callback?" + url.Values{"state": {state}, "code": {code}}.Encode()
}

// TestLoginRedirect checks what /login sends: the exact registered redirect
// URI, PKCE with S256 bound to the verifier in the cookie, a fresh state each
// time, and a cookie a script cannot read and a cross-site page cannot send.
func TestLoginRedirect(t *testing.T) {
	h, p := plainHandler(t, false)
	q, cookie, r := startFlow(t, h)

	if got := q.Get("redirect_uri"); got != testRedirect {
		t.Errorf("redirect_uri %q, want %q", got, testRedirect)
	}
	if q.Get("code_challenge_method") != "S256" || q.Get("state") == "" || q.Get("client_id") != testClientID {
		t.Errorf("authorization request is missing PKCE, state or client id: %v", q)
	}
	state, _, verifier, ok := readFlowCookie(requestWith(cookie))
	if !ok || state != q.Get("state") {
		t.Fatal("the cookie does not hold the state of the redirect")
	}
	sum := sha256.Sum256([]byte(verifier))
	if q.Get("code_challenge") != base64.RawURLEncoding.EncodeToString(sum[:]) {
		t.Error("code_challenge is not the S256 of the stored verifier")
	}
	if loc := r.header.Get("Location"); !strings.HasPrefix(loc, p.srv.URL+"/auth?") {
		t.Errorf("redirect leaves for %q, not the provider", loc)
	}

	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode || cookie.Path != "/callback" || cookie.MaxAge <= 0 || cookie.MaxAge > 300 {
		t.Errorf("cookie attributes: %+v", cookie)
	}
	if cookie.Secure {
		t.Error("a plain-http request got a Secure cookie")
	}
	if r.header.Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control %q, want no-store", r.header.Get("Cache-Control"))
	}

	q2, _, _ := startFlow(t, h)
	if q2.Get("state") == q.Get("state") || q2.Get("code_challenge") == q.Get("code_challenge") {
		t.Error("two logins share a state or a PKCE challenge")
	}

	secure := do(t, h, http.MethodGet, "/login", "", nil, map[string]string{"X-Forwarded-Proto": "https"})
	if len(secure.cookies) != 1 || !secure.cookies[0].Secure {
		t.Error("a request that arrived over TLS got a cookie without Secure")
	}
}

// TestLoginIgnoresRequestParameters tries to steer the redirect, the state and
// the client through the login URL.
func TestLoginIgnoresRequestParameters(t *testing.T) {
	h, p := plainHandler(t, false)
	r := do(t, h, http.MethodGet,
		"/login?redirect_uri=https://evil.example/cb&state=fixed&next=https://evil.example&client_id=other&code_challenge=x", "", nil, nil)
	loc, _ := url.Parse(r.header.Get("Location"))
	if !strings.HasPrefix(r.header.Get("Location"), p.srv.URL+"/auth?") {
		t.Errorf("redirect leaves for %q", r.header.Get("Location"))
	}
	q := loc.Query()
	if q.Get("redirect_uri") != testRedirect || q.Get("state") == "fixed" || q.Get("client_id") != testClientID || q.Get("code_challenge") == "x" {
		t.Errorf("a request parameter reached the authorization request: %v", q)
	}
}

// TestUnexpectedMethodsAndRoutes allows exactly the routes the flow uses.
func TestUnexpectedMethodsAndRoutes(t *testing.T) {
	h, _ := plainHandler(t, false)
	cases := []struct {
		method, target string
		want           int
	}{
		{http.MethodPost, "/login", http.StatusMethodNotAllowed},
		{http.MethodPut, "/callback", http.StatusMethodNotAllowed},
		{http.MethodDelete, "/callback", http.StatusMethodNotAllowed},
		{http.MethodPost, "/callback", http.StatusMethodNotAllowed},
		{http.MethodGet, "/", http.StatusNotFound},
		{http.MethodGet, "/admin", http.StatusNotFound},
	}
	for _, tc := range cases {
		if r := do(t, h, tc.method, tc.target, "", nil, nil); r.code != tc.want {
			t.Errorf("%s %s: status %d, want %d", tc.method, tc.target, r.code, tc.want)
		}
	}
}

// TestCallbackRefusals sends callbacks that must never reach the token
// endpoint: no cookie, a planted cookie with an empty secret, a state that does
// not match or is repeated, and a refusal from the provider.
func TestCallbackRefusals(t *testing.T) {
	_, validCookie, _ := startFlow(t, mustHandler(t))
	good := forgedCookie("state-1", "nonce-1", "verifier-1")

	cases := []struct {
		name   string
		target string
		cookie *http.Cookie
		want   int
	}{
		{"no cookie", callbackTarget("state-1", "c"), nil, http.StatusBadRequest},
		{"cookie is not base64", callbackTarget("state-1", "c"), &http.Cookie{Name: flowCookieName, Value: "!!"}, http.StatusBadRequest},
		{"cookie has two parts", callbackTarget("s", "c"), &http.Cookie{Name: flowCookieName, Value: base64.RawURLEncoding.EncodeToString([]byte("a|b"))}, http.StatusBadRequest},
		{"empty state, no state sent", "/callback?code=c", forgedCookie("", "n", "v"), http.StatusBadRequest},
		{"empty state, empty state sent", callbackTarget("", "c"), forgedCookie("", "n", "v"), http.StatusBadRequest},
		{"empty verifier", callbackTarget("state-1", "c"), forgedCookie("state-1", "n", ""), http.StatusBadRequest},
		{"state missing", "/callback?code=c", good, http.StatusBadRequest},
		{"state mismatch", callbackTarget("other", "c"), good, http.StatusBadRequest},
		{"state from another flow", callbackTarget("state-1", "c"), validCookie, http.StatusBadRequest},
		{"state repeated", "/callback?state=state-1&state=state-1&code=c", good, http.StatusBadRequest},
		{"code missing", "/callback?state=state-1", good, http.StatusBadRequest},
		{"code empty", callbackTarget("state-1", ""), good, http.StatusBadRequest},
		{"code repeated", "/callback?state=state-1&code=a&code=b", good, http.StatusBadRequest},
		{"provider refused", "/callback?state=state-1&error=access_denied&error_description=%3Cscript%3Ealert(1)%3C/script%3E", good, http.StatusUnauthorized},
		{"refused, repeated error", "/callback?state=state-1&error=a&error=b&code=c", good, http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, p := plainHandler(t, false)
			r := do(t, h, http.MethodGet, tc.target, "", tc.cookie, nil)
			if r.code != tc.want {
				t.Errorf("status %d, want %d", r.code, tc.want)
			}
			if p.tokenCalls() != 0 {
				t.Error("the token endpoint was contacted")
			}
			if strings.Contains(r.body, "script") || strings.Contains(r.body, "access_denied") {
				t.Errorf("the provider's text was echoed: %q", r.body)
			}
			if len(r.cookies) != 1 || r.cookies[0].MaxAge >= 0 {
				t.Error("the flow cookie was not spent")
			}
		})
	}
}

// mustHandler builds a throwaway handler to mint a cookie from another flow.
func mustHandler(t *testing.T) http.Handler {
	t.Helper()
	h, _ := plainHandler(t, false)
	return h
}

// TestCallbackSuccess walks login and callback, then checks exactly what the
// provider received and that the flow cookie is spent.
func TestCallbackSuccess(t *testing.T) {
	h, p := plainHandler(t, false)
	q, cookie, _ := startFlow(t, h)
	_, _, verifier, _ := readFlowCookie(requestWith(cookie))

	r := do(t, h, http.MethodGet, callbackTarget(q.Get("state"), "code-xyz"), "", cookie, nil)
	if r.code != http.StatusOK || !strings.Contains(r.body, `"login":"ana"`) {
		t.Fatalf("callback: status %d body %q", r.code, r.body)
	}
	if r.header.Get("Cache-Control") != "no-store" {
		t.Error("the identity response is cacheable")
	}
	if len(r.cookies) != 1 || r.cookies[0].MaxAge >= 0 || r.cookies[0].Path != "/callback" {
		t.Errorf("the flow cookie was not spent: %+v", r.cookies)
	}

	form := p.lastForm()
	if form.Get("code") != "code-xyz" || form.Get("code_verifier") != verifier ||
		form.Get("redirect_uri") != testRedirect || form.Get("grant_type") != "authorization_code" {
		t.Errorf("token request: %v", form)
	}
	if p.tokenCalls() != 1 {
		t.Errorf("%d token requests, want 1", p.tokenCalls())
	}
}

// TestExchangeFailureIsGeneric makes the provider answer the exchange with an
// error carrying text of its own. The page and the log must not repeat it.
func TestExchangeFailureIsGeneric(t *testing.T) {
	h, p := plainHandler(t, false)
	p.tokenStatus = http.StatusBadRequest
	p.tokenBody = `{"error":"invalid_grant","error_description":"leak-from-provider"}`
	q, cookie, _ := startFlow(t, h)

	var logged strings.Builder
	captureLog(t, &logged)
	r := do(t, h, http.MethodGet, callbackTarget(q.Get("state"), "code-xyz"), "", cookie, nil)
	if r.code != http.StatusUnauthorized || strings.Contains(r.body, "leak-from-provider") {
		t.Errorf("status %d, body %q", r.code, r.body)
	}
	if strings.Contains(logged.String(), "leak-from-provider") {
		t.Error("the provider's error text reached the log")
	}
}

// TestNoSecretsInLogs runs a good flow and failing ones with the log captured.
func TestNoSecretsInLogs(t *testing.T) {
	var logged strings.Builder
	captureLog(t, &logged)

	h, _ := plainHandler(t, false)
	q, cookie, _ := startFlow(t, h)
	_, _, verifier, _ := readFlowCookie(requestWith(cookie))
	do(t, h, http.MethodGet, callbackTarget(q.Get("state"), "code-xyz"), "", cookie, nil)
	do(t, h, http.MethodGet, callbackTarget("wrong", "code-xyz"), "", cookie, nil)
	do(t, h, http.MethodGet, "/callback?state="+q.Get("state")+"&error=access_denied", "", cookie, nil)

	for name, secret := range map[string]string{
		"access token": accessSecret, "client secret": testClientSecret, "code": "code-xyz",
		"verifier": verifier, "state": q.Get("state"),
	} {
		if strings.Contains(logged.String(), secret) {
			t.Errorf("the %s is in the log", name)
		}
	}
}

// TestServerHasTimeouts guards the slow-client defences.
func TestServerHasTimeouts(t *testing.T) {
	srv := newServer(":0", http.NotFoundHandler())
	if srv.ReadHeaderTimeout <= 0 || srv.ReadTimeout <= 0 || srv.WriteTimeout <= 0 || srv.IdleTimeout <= 0 {
		t.Errorf("a server timeout is unset: %+v", srv)
	}
	if srv.MaxHeaderBytes <= 0 || srv.MaxHeaderBytes > 1<<20 {
		t.Errorf("MaxHeaderBytes %d is not a small explicit bound", srv.MaxHeaderBytes)
	}
}
