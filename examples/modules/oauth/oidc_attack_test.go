package main

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// oidcHandler returns the example's handler over a fake OIDC provider.
func oidcHandler(t *testing.T) (http.Handler, *fakeProvider) {
	t.Helper()
	p := newFakeProvider(t)
	return newHandler(p.client(t, true), true, false), p
}

// TestOIDCNonceIsEnforced checks that the nonce in the cookie is the one the
// ID token must carry. A token minted for another flow is refused even though
// its signature, issuer and audience are fine.
func TestOIDCNonceIsEnforced(t *testing.T) {
	h, p := oidcHandler(t)
	q, cookie, _ := startFlow(t, h)

	p.idToken = p.sign(t, p.key, p.idClaims(q.Get("nonce")))
	r := do(t, h, http.MethodGet, callbackTarget(q.Get("state"), "c"), "", cookie, nil)
	if r.code != http.StatusOK || !strings.Contains(r.body, "user-42") {
		t.Fatalf("matching nonce: status %d body %q", r.code, r.body)
	}

	q, cookie, _ = startFlow(t, h)
	p.idToken = p.sign(t, p.key, p.idClaims("a-nonce-from-another-flow"))
	r = do(t, h, http.MethodGet, callbackTarget(q.Get("state"), "c"), "", cookie, nil)
	if r.code != http.StatusUnauthorized || strings.Contains(r.body, "user-42") {
		t.Errorf("foreign nonce: status %d body %q", r.code, r.body)
	}

	q, cookie, _ = startFlow(t, h)
	claims := p.idClaims(q.Get("nonce"))
	delete(claims, "nonce")
	p.idToken = p.sign(t, p.key, claims)
	r = do(t, h, http.MethodGet, callbackTarget(q.Get("state"), "c"), "", cookie, nil)
	if r.code != http.StatusUnauthorized {
		t.Errorf("token without a nonce: status %d, want 401", r.code)
	}
}

// TestOIDCRefusesForgedIdentity feeds the callback ID tokens it must not
// accept, each with a valid state and code.
func TestOIDCRefusesForgedIdentity(t *testing.T) {
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]func(p *fakeProvider, nonce string) string{
		"no id_token":          func(*fakeProvider, string) string { return "" },
		"signed by a stranger": func(p *fakeProvider, n string) string { return p.sign(t, other, p.idClaims(n)) },
		"another audience": func(p *fakeProvider, n string) string {
			c := p.idClaims(n)
			c["aud"] = "someone-else"
			return p.sign(t, p.key, c)
		},
		"another issuer": func(p *fakeProvider, n string) string {
			c := p.idClaims(n)
			c["iss"] = "https://evil.example"
			return p.sign(t, p.key, c)
		},
		"expired": func(p *fakeProvider, n string) string {
			c := p.idClaims(n)
			c["exp"] = 1
			return p.sign(t, p.key, c)
		},
		"garbage": func(*fakeProvider, string) string { return "a.b.c" },
	}
	for name, mint := range cases {
		t.Run(name, func(t *testing.T) {
			h, p := oidcHandler(t)
			q, cookie, _ := startFlow(t, h)
			p.idToken = mint(p, q.Get("nonce"))
			r := do(t, h, http.MethodGet, callbackTarget(q.Get("state"), "c"), "", cookie, nil)
			if r.code != http.StatusUnauthorized || strings.Contains(r.body, "user-42") {
				t.Errorf("status %d body %q", r.code, r.body)
			}
		})
	}
}

// TestCrossSiteCallback covers the form_post flow Apple uses: the cookie must
// survive a cross-site POST, the parameters come from the body alone, and the
// body is bounded.
func TestCrossSiteCallback(t *testing.T) {
	p := newFakeProvider(t)
	h := newHandler(p.client(t, false), false, true)
	q, cookie, _ := startFlow(t, h)

	if !cookie.Secure || cookie.SameSite != http.SameSiteNoneMode || !cookie.HttpOnly {
		t.Errorf("cookie attributes for a cross-site POST: %+v", cookie)
	}

	form := url.Values{"state": {q.Get("state")}, "code": {"c"}}.Encode()

	t.Run("parameters in the query of a POST are ignored", func(t *testing.T) {
		r := do(t, h, http.MethodPost, "/callback?"+form, "", cookie, nil)
		if r.code != http.StatusBadRequest || p.tokenCalls() != 0 {
			t.Errorf("status %d, token calls %d", r.code, p.tokenCalls())
		}
	})
	t.Run("oversized body", func(t *testing.T) {
		r := do(t, h, http.MethodPost, "/callback", form+"&junk="+strings.Repeat("x", 1<<20), cookie, nil)
		if r.code != http.StatusRequestEntityTooLarge || p.tokenCalls() != 0 {
			t.Errorf("status %d, token calls %d", r.code, p.tokenCalls())
		}
	})
	t.Run("valid post", func(t *testing.T) {
		r := do(t, h, http.MethodPost, "/callback", form, cookie, nil)
		if r.code != http.StatusOK || p.tokenCalls() != 1 {
			t.Errorf("status %d, token calls %d", r.code, p.tokenCalls())
		}
	})
}
