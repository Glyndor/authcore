package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/oauth"
)

const (
	testClientID     = "client-id-1"
	testClientSecret = "client-secret-do-not-log"
	testRedirect     = "http://localhost:8080/callback"
	accessSecret     = "AT-secret-value-do-not-log"
)

// fakeProvider is an authorization server on the loopback interface. It
// records every token request, so a test can tell what the example sent and
// whether it contacted the provider at all.
type fakeProvider struct {
	srv *httptest.Server
	key *rsa.PrivateKey

	mu         sync.Mutex
	tokenForms []url.Values
	userinfoAs []string

	// tokenStatus and tokenBody replace the token response when set.
	tokenStatus int
	tokenBody   string
	// idToken, when set, is returned as the id_token of the token response.
	idToken string
}

func newFakeProvider(t *testing.T) *fakeProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &fakeProvider{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("/token", p.token)
	mux.HandleFunc("/jwks", p.jwks)
	mux.HandleFunc("/userinfo", p.userinfo)
	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	return p
}

func (p *fakeProvider) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	p.mu.Lock()
	p.tokenForms = append(p.tokenForms, r.PostForm)
	status, body, idToken := p.tokenStatus, p.tokenBody, p.idToken
	p.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	if status != 0 {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
		return
	}
	out := map[string]any{"access_token": accessSecret, "token_type": "Bearer", "expires_in": 60}
	if idToken != "" {
		out["id_token"] = idToken
	}
	_ = json.NewEncoder(w).Encode(out)
}

func (p *fakeProvider) jwks(w http.ResponseWriter, _ *http.Request) {
	pub := p.key.PublicKey
	_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
		"kty": "RSA", "kid": "k1", "alg": "RS256", "use": "sig",
		"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}}})
}

func (p *fakeProvider) userinfo(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	p.userinfoAs = append(p.userinfoAs, r.Header.Get("Authorization"))
	p.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer "+accessSecret {
		http.Error(w, "no", http.StatusUnauthorized)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"id": "42", "login": "ana"})
}

// tokenCalls returns how many times the token endpoint was contacted.
func (p *fakeProvider) tokenCalls() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.tokenForms)
}

// lastForm returns the form of the latest token request.
func (p *fakeProvider) lastForm() url.Values {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.tokenForms) == 0 {
		return nil
	}
	return p.tokenForms[len(p.tokenForms)-1]
}

// sign builds an RS256 ID token over claims with the key signing as kid k1.
func (p *fakeProvider) sign(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	enc := base64.RawURLEncoding.EncodeToString
	head, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": "k1"})
	body, _ := json.Marshal(claims)
	signing := enc(head) + "." + enc(body)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return signing + "." + enc(sig)
}

// idClaims returns valid claims for the provider, bound to nonce.
func (p *fakeProvider) idClaims(nonce string) map[string]any {
	now := time.Now()
	return map[string]any{
		"iss": p.srv.URL, "aud": testClientID, "sub": "user-42", "nonce": nonce,
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
		"email": "ana@example.com", "email_verified": true,
	}
}

// client builds an oauth client for the provider: OIDC when oidc is set,
// plain OAuth2 with a userinfo endpoint otherwise.
func (p *fakeProvider) client(t *testing.T, oidc bool) *oauth.Client {
	t.Helper()
	auth, err := authcore.New(authcore.Config{KeysDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	prov := oauth.Provider{AuthURL: p.srv.URL + "/auth", TokenURL: p.srv.URL + "/token"}
	if oidc {
		prov.Issuer, prov.JWKSURL = p.srv.URL, p.srv.URL+"/jwks"
	} else {
		prov.UserInfoURL = p.srv.URL + "/userinfo"
	}
	mod, err := oauth.New(auth, oauth.Config{
		ClientID: testClientID, ClientSecret: testClientSecret, RedirectURL: testRedirect,
		Provider: prov, Scopes: []string{"openid", "email"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return mod
}

// reply is one recorded response.
type reply struct {
	code    int
	header  http.Header
	body    string
	cookies []*http.Cookie
}

// do sends one request to h. cookie, when not nil, is attached as sent.
func do(t *testing.T, h http.Handler, method, target, form string, cookie *http.Cookie, headers map[string]string) reply {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), method, target, strings.NewReader(form))
	if form != "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	res := rec.Result()
	defer res.Body.Close()
	return reply{code: rec.Code, header: rec.Header(), body: rec.Body.String(), cookies: res.Cookies()}
}

// startFlow calls /login and returns the redirect target's query, the flow
// cookie as the browser would send it back, and the raw reply.
func startFlow(t *testing.T, h http.Handler) (query url.Values, cookie *http.Cookie, r reply) {
	t.Helper()
	r = do(t, h, http.MethodGet, "/login", "", nil, nil)
	if r.code != http.StatusFound || len(r.cookies) != 1 {
		t.Fatalf("login: status %d, %d cookies", r.code, len(r.cookies))
	}
	loc, err := url.Parse(r.header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return loc.Query(), r.cookies[0], r
}

// requestWith returns a request that carries cookie, for readFlowCookie.
func requestWith(cookie *http.Cookie) *http.Request {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/callback", nil)
	req.AddCookie(cookie)
	return req
}

// captureLog sends the standard logger to w until the test ends.
func captureLog(t *testing.T, w *strings.Builder) {
	t.Helper()
	log.SetOutput(w)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
}

// forgedCookie is a flow cookie an attacker who can plant cookies would send.
func forgedCookie(state, nonce, verifier string) *http.Cookie {
	value := base64.RawURLEncoding.EncodeToString([]byte(state + "|" + nonce + "|" + verifier))
	return &http.Cookie{Name: flowCookieName, Value: value}
}
