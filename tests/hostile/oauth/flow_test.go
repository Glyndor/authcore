package hostile_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth"
)

// Attacker: the person at the browser (they can replay a callback, swap a
// code, forge a state) and a hostile or buggy authorization server. Effects
// they want: log in as someone else with a token or code that belongs to
// another request, downgrade PKCE, or make the client leak its secret.

// fakeAS is an authorization server that enforces what a correct one
// enforces: single-use codes, PKCE S256, the registered redirect_uri, the
// client secret, and a nonce echoed into the ID token.
type fakeAS struct {
	mu      sync.Mutex
	codes   map[string]*grant
	secret  string
	redir   string
	tokens  atomic.Int64 // token-endpoint requests received
	lastRaw url.Values
	lastHdr http.Header
	lastURL string
	t       *testing.T
}

type grant struct {
	challenge, nonce string
	used             bool
}

func newFakeAS(t *testing.T, secret, redirect string) *fakeAS {
	return &fakeAS{t: t, codes: map[string]*grant{}, secret: secret, redir: redirect}
}

// authorize plays the browser leg: it reads the authorization URL the client
// built and returns the code the user is redirected back with.
func (as *fakeAS) authorize(t *testing.T, authURL string) string {
	t.Helper()
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	for _, k := range []string{"response_type", "client_id", "redirect_uri", "scope", "state", "nonce", "code_challenge", "code_challenge_method"} {
		if len(q[k]) != 1 {
			t.Fatalf("authorization URL carries %q %d times: %s", k, len(q[k]), authURL)
		}
	}
	if q.Get("code_challenge_method") != "S256" || q.Get("response_type") != "code" || q.Get("redirect_uri") != as.redir {
		t.Fatalf("authorization request is weaker than required: %v", q)
	}
	code := fmt.Sprintf("code-%d", len(as.codes)+1)
	as.mu.Lock()
	as.codes[code] = &grant{challenge: q.Get("code_challenge"), nonce: q.Get("nonce")}
	as.mu.Unlock()
	return code
}

func (as *fakeAS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	as.tokens.Add(1)
	_ = r.ParseForm()
	as.mu.Lock()
	as.lastRaw, as.lastHdr, as.lastURL = r.PostForm, r.Header.Clone(), r.URL.String()
	g := as.codes[r.PostForm.Get("code")]
	reject := func(reason string) {
		as.mu.Unlock()
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant", "error_description": reason})
	}
	switch {
	case r.PostForm.Get("grant_type") != "authorization_code":
		reject("grant_type")
	case g == nil:
		reject("unknown code")
	case g.used:
		g.used = true
		reject("code already used")
	case r.PostForm.Get("redirect_uri") != as.redir:
		reject("redirect_uri mismatch")
	case !pkceMatches(g.challenge, r.PostForm.Get("code_verifier")):
		g.used = true
		reject("pkce")
	case !as.authenticated(r):
		reject("bad client authentication")
	default:
		g.used = true
		nonce := g.nonce
		as.mu.Unlock()
		a, _ := rsaKeys()
		idt := mint{Key: a, Claims: claims(nonce, nil)}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "id_token": idt.String(as.t), "expires_in": 3600})
	}
}

func (as *fakeAS) authenticated(r *http.Request) bool {
	if as.secret == "" {
		return true
	}
	if u, p, ok := r.BasicAuth(); ok {
		uu, _ := url.QueryUnescape(u)
		pp, _ := url.QueryUnescape(p)
		return uu == testClient && pp == as.secret
	}
	return r.PostForm.Get("client_secret") == as.secret
}

func pkceMatches(challenge, verifier string) bool {
	sum := sha256.Sum256([]byte(verifier))
	return verifier != "" && base64.RawURLEncoding.EncodeToString(sum[:]) == challenge
}

// flowRig wires a client to a fakeAS and a JWKS that signs for keyA.
func flowRig(t *testing.T, secret string, mut func(*oauth.Config)) (*oauth.Client, *fakeAS) {
	t.Helper()
	a, _ := rsaKeys()
	redirect := "https://app.example/cb"
	as := newFakeAS(t, secret, redirect)
	asSrv := serve(t, as)
	jwks := serve(t, staticBody(jwksDoc(rsaJWK(testKID, &a.PublicKey, nil))))
	c := oidcClient(t, jwks.URL, func(c *oauth.Config) {
		c.RedirectURL = redirect
		c.ClientSecret = secret
		c.Provider.TokenURL = asSrv.URL
		if mut != nil {
			mut(c)
		}
	})
	return c, as
}

func TestHostile_Flow_aCorrectLoginWorksEndToEnd(t *testing.T) {
	// The control every attack below is measured against.
	c, as := flowRig(t, "s3cr3t", nil)
	req, err := c.AuthCodeURL()
	if err != nil {
		t.Fatal(err)
	}
	code := as.authorize(t, req.URL)
	tok, err := c.Exchange(ctx(t), code, req.Verifier)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	claimsOut, err := c.VerifyIDToken(ctx(t), tok.IDToken, req.Nonce)
	if err != nil || claimsOut.Subject != "user-abc" {
		t.Fatalf("VerifyIDToken = %+v, %v", claimsOut, err)
	}
}

func TestHostile_Flow_stateNonceAndVerifierAreUnpredictableAndPerRequest(t *testing.T) {
	c, _ := flowRig(t, "", nil)
	seen := map[string]string{}
	const n = 500
	for range n {
		r, err := c.AuthCodeURL()
		if err != nil {
			t.Fatal(err)
		}
		for kind, v := range map[string]string{"state": r.State, "nonce": r.Nonce, "verifier": r.Verifier} {
			if len(v) < 43 {
				t.Fatalf("%s %q has under 256 bits of entropy", kind, v)
			}
			if strings.Trim(v, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") != "" {
				t.Fatalf("%s %q is not base64url", kind, v)
			}
			if prev, dup := seen[v]; dup {
				t.Fatalf("%s repeats the earlier %s %q", kind, prev, v)
			}
			seen[v] = kind
		}
		u, _ := url.Parse(r.URL)
		q := u.Query()
		if q.Get("state") != r.State || q.Get("nonce") != r.Nonce {
			t.Fatal("the URL does not carry the state and nonce it returned")
		}
		sum := sha256.Sum256([]byte(r.Verifier))
		if q.Get("code_challenge") != base64.RawURLEncoding.EncodeToString(sum[:]) || q.Get("code_challenge_method") != "S256" {
			t.Fatalf("code challenge is not S256 of the verifier: %v", q)
		}
	}
	if len(seen) != 3*n {
		t.Fatalf("expected %d distinct secrets, got %d", 3*n, len(seen))
	}
}

// Whatever sits in the configured values, the authorization URL carries each
// security parameter exactly once and with the value the library generated.
func TestHostile_Flow_configValuesCannotInjectOrOverrideAuthorizationParameters(t *testing.T) {
	hostileID := "id&redirect_uri=https://evil.example&state=evil"
	hostileRedirect := "https://app.example/cb?state=evil&nonce=evil&code_challenge=evil#frag"
	cfgMut := func(c *oauth.Config) {
		c.ClientID = hostileID
		c.RedirectURL = hostileRedirect
		c.Scopes = []string{"openid", "x&response_type=token", "a b\nc", "é"}
		// A pre-seeded authorization URL that tries to pin the values and downgrade PKCE.
		c.Provider.AuthURL = "https://idp.example/auth?state=evil&nonce=evil&code_challenge=evil&code_challenge_method=plain&response_type=token&client_id=evil&redirect_uri=https://evil.example&scope=admin"
	}
	c := oidcClient(t, "https://idp.example/jwks", cfgMut)
	r, err := c.AuthCodeURL()
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(r.URL)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	want := map[string]string{
		"response_type": "code", "client_id": hostileID, "redirect_uri": hostileRedirect,
		"scope": "openid x&response_type=token a b\nc é", "state": r.State, "nonce": r.Nonce, "code_challenge_method": "S256",
	}
	for k, v := range want {
		if len(q[k]) != 1 || q.Get(k) != v {
			t.Errorf("%s = %q (x%d), want exactly %q", k, q[k], len(q[k]), v)
		}
	}
	if len(q["code_challenge"]) != 1 || q.Get("code_challenge") == "evil" {
		t.Errorf("code_challenge = %q", q["code_challenge"])
	}
	for k := range q {
		if _, known := want[k]; !known && k != "code_challenge" {
			t.Errorf("unexpected parameter %q = %q", k, q[k])
		}
	}
	if strings.Contains(u.Fragment, "state") {
		t.Errorf("the redirect fragment leaked into the URL fragment: %q", u.Fragment)
	}
}

func TestHostile_Flow_attacksOnTheCodeExchange(t *testing.T) {
	t.Run("a verifier from another login is refused by the server", func(t *testing.T) {
		c, as := flowRig(t, "s3cr3t", nil)
		victim, _ := c.AuthCodeURL()
		attacker, _ := c.AuthCodeURL()
		code := as.authorize(t, victim.URL)
		if tok, err := c.Exchange(ctx(t), code, attacker.Verifier); err == nil {
			t.Fatalf("a code was exchanged with someone else's verifier: %+v", tok)
		}
	})
	t.Run("a code cannot be exchanged twice", func(t *testing.T) {
		c, as := flowRig(t, "s3cr3t", nil)
		r, _ := c.AuthCodeURL()
		code := as.authorize(t, r.URL)
		if _, err := c.Exchange(ctx(t), code, r.Verifier); err != nil {
			t.Fatalf("control: first exchange failed: %v", err)
		}
		if tok, err := c.Exchange(ctx(t), code, r.Verifier); err == nil {
			t.Fatalf("a replayed code produced tokens: %+v", tok)
		}
	})
	t.Run("a token from another login fails the nonce check", func(t *testing.T) {
		c, as := flowRig(t, "s3cr3t", nil)
		victim, _ := c.AuthCodeURL()
		attacker, _ := c.AuthCodeURL()
		tok, err := c.Exchange(ctx(t), as.authorize(t, victim.URL), victim.Verifier)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := c.VerifyIDToken(ctx(t), tok.IDToken, attacker.Nonce); err == nil {
			t.Fatalf("the victim's token was accepted for the attacker's login: %+v", got)
		}
	})
	t.Run("empty code or verifier never reaches the server", func(t *testing.T) {
		c, as := flowRig(t, "s3cr3t", nil)
		for _, args := range [][2]string{{"", "v"}, {"c", ""}, {"", ""}} {
			if _, err := c.Exchange(ctx(t), args[0], args[1]); err == nil {
				t.Errorf("Exchange(%q, %q) succeeded", args[0], args[1])
			}
		}
		if n := as.tokens.Load(); n != 0 {
			t.Fatalf("%d requests reached the token endpoint", n)
		}
	})
	t.Run("a failed exchange is not retried", func(t *testing.T) {
		var hits atomic.Int64
		srv := serve(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			hits.Add(1)
			http.Error(w, "down", http.StatusServiceUnavailable)
		}))
		c := tokenClient(t, srv.URL, func(c *oauth.Config) { c.ClientSecret = "s3cr3t" })
		if _, err := c.Exchange(ctx(t), "code", "verifier"); err == nil {
			t.Fatal("a 503 was accepted")
		}
		if hits.Load() != 1 {
			t.Fatalf("one Exchange sent %d requests; an authorization code may be presented once", hits.Load())
		}
	})
	t.Run("a cancelled context sends nothing", func(t *testing.T) {
		c, as := flowRig(t, "s3cr3t", nil)
		cc, cancel := contextCancelled()
		defer cancel()
		if _, err := c.Exchange(cc, "code", "verifier"); err == nil {
			t.Fatal("a cancelled Exchange succeeded")
		}
		if as.tokens.Load() != 0 {
			t.Fatal("a cancelled Exchange still reached the server")
		}
	})
	t.Run("the redirect_uri sent is the configured one, whatever the code says", func(t *testing.T) {
		c, as := flowRig(t, "s3cr3t", nil)
		r, _ := c.AuthCodeURL()
		code := as.authorize(t, r.URL)
		if _, err := c.Exchange(ctx(t), code+"&redirect_uri=https://evil.example", r.Verifier); err == nil {
			t.Fatal("a doctored code was accepted")
		}
		if got := as.lastRaw["redirect_uri"]; len(got) != 1 || got[0] != "https://app.example/cb" {
			t.Fatalf("redirect_uri on the wire = %q", got)
		}
	})
}

// Values that reach the token endpoint are form-encoded: they cannot add parameters.
func TestHostile_Flow_codeAndVerifierCannotInjectFormParameters(t *testing.T) {
	c, as := flowRig(t, "s3cr3t", nil)
	code := "abc&grant_type=password&client_id=evil&username=admin"
	verifier := "v%26client_secret=x&redirect_uri=https://evil.example\r\nX-Evil: 1"
	_, _ = c.Exchange(ctx(t), code, verifier)
	for _, k := range []string{"grant_type", "client_id", "redirect_uri", "client_secret"} {
		if len(as.lastRaw[k]) != 1 {
			t.Errorf("%s appears %d times on the wire", k, len(as.lastRaw[k]))
		}
	}
	if as.lastRaw.Get("grant_type") != "authorization_code" || as.lastRaw.Get("client_id") != testClient {
		t.Errorf("a parameter was overridden: %v", as.lastRaw)
	}
	if as.lastRaw.Get("code") != code || as.lastRaw.Get("code_verifier") != verifier {
		t.Errorf("code or verifier altered on the wire: %q %q", as.lastRaw.Get("code"), as.lastRaw.Get("code_verifier"))
	}
	if as.lastRaw.Has("username") {
		t.Error("an injected parameter reached the server")
	}
}

func TestHostile_Flow_clientAuthenticationNeverLeaksTheSecret(t *testing.T) {
	const secret = "s3cr3t:with+odd/chars%and space"
	const id = "client:with:colons"
	t.Run("post: the secret is in the body only", func(t *testing.T) {
		c, as := flowRig(t, secret, func(c *oauth.Config) { c.ClientID = id; c.Provider.AuthMethods = []string{"client_secret_post"} })
		as.secret = secret
		r, _ := c.AuthCodeURL()
		_, _ = c.Exchange(ctx(t), as.authorize(t, r.URL), r.Verifier)
		if as.lastRaw.Get("client_secret") != secret {
			t.Fatalf("the secret did not arrive intact: %q", as.lastRaw.Get("client_secret"))
		}
		if strings.Contains(as.lastURL, "secret") || as.lastHdr.Get("Authorization") != "" {
			t.Fatalf("the secret is also in the URL or the Authorization header: %q %q", as.lastURL, as.lastHdr.Get("Authorization"))
		}
	})
	t.Run("basic: the secret is in the header only, form-encoded per RFC 6749", func(t *testing.T) {
		c, as := flowRig(t, secret, func(c *oauth.Config) {
			c.ClientID = id
			c.Provider.AuthMethods = []string{"CLIENT_SECRET_BASIC", "client_secret_post"}
		})
		r, _ := c.AuthCodeURL()
		_, _ = c.Exchange(ctx(t), as.authorize(t, r.URL), r.Verifier)
		hdr := as.lastHdr.Get("Authorization")
		raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(hdr, "Basic "))
		if err != nil {
			t.Fatalf("no Basic header: %q", hdr)
		}
		gotID, gotSecret, _ := strings.Cut(string(raw), ":")
		if u, _ := url.QueryUnescape(gotID); u != id {
			t.Errorf("client id on the wire = %q, want the form-encoding of %q", gotID, id)
		}
		if p, _ := url.QueryUnescape(gotSecret); p != secret {
			t.Errorf("secret on the wire = %q, want the form-encoding of %q", gotSecret, secret)
		}
		if as.lastRaw.Has("client_secret") {
			t.Error("the secret is also in the body")
		}
	})
	t.Run("only unsupported methods advertised: refused before any request", func(t *testing.T) {
		for _, methods := range [][]string{{"none"}, {"private_key_jwt"}, {"client_secret_jwt", "tls_client_auth"}, {""}, {"client_secret_basic_not"}} {
			c, as := flowRig(t, secret, func(c *oauth.Config) { c.Provider.AuthMethods = methods })
			if _, err := c.Exchange(ctx(t), "code", "verifier"); err == nil {
				t.Errorf("methods %v: the secret was sent to a server that advertised no usable method", methods)
			}
			if n := as.tokens.Load(); n != 0 {
				t.Errorf("methods %v: %d request(s) were sent", methods, n)
			}
		}
	})
	t.Run("a public client sends no credentials, whatever is advertised", func(t *testing.T) {
		c, as := flowRig(t, "", func(c *oauth.Config) { c.Provider.AuthMethods = []string{"none"} })
		r, _ := c.AuthCodeURL()
		if _, err := c.Exchange(ctx(t), as.authorize(t, r.URL), r.Verifier); err != nil {
			t.Fatalf("public client: %v", err)
		}
		if as.lastHdr.Get("Authorization") != "" || as.lastRaw.Has("client_secret") {
			t.Fatal("a public client sent credentials")
		}
	})
}

func TestHostile_Flow_secretsStayOutOfLogsAndBadSecretSourcesSendNothing(t *testing.T) {
	const secret = "s3cr3t:with+odd/chars%and space"
	t.Run("neither logs nor errors contain the secret or the code", func(t *testing.T) {
		log := &captureLogger{}
		srv := serve(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "nope", 400) }))
		cfg := oauth.Config{
			ClientID: testClient, ClientSecret: secret, RedirectURL: "https://app.example/cb",
			Provider: oauth.Provider{Issuer: testIssuer, AuthURL: "https://idp.example/auth", TokenURL: srv.URL, JWKSURL: "https://idp.example/jwks"},
		}
		c, err := oauth.New(silentProvider{log: log}, cfg)
		if err != nil {
			t.Fatal(err)
		}
		_, err = c.Exchange(ctx(t), "the-secret-code", "the-secret-verifier")
		_, _ = c.VerifyIDToken(ctx(t), "a.b.c", "n")
		all := log.String()
		if err != nil {
			all += err.Error()
		}
		for _, leak := range []string{secret, "the-secret-code", "the-secret-verifier"} {
			if strings.Contains(all, leak) {
				t.Fatalf("%q leaked into logs or errors: %s", leak, all)
			}
		}
	})
	t.Run("secret function failures and empty secrets send nothing", func(t *testing.T) {
		for name, fn := range map[string]func(context.Context) (string, error){
			"error": func(context.Context) (string, error) { return "", fmt.Errorf("vault down") },
			"empty": func(context.Context) (string, error) { return "", nil },
		} {
			c, as := flowRig(t, "", func(c *oauth.Config) { c.ClientSecretFunc = fn })
			if _, err := c.Exchange(ctx(t), "code", "verifier"); err == nil {
				t.Errorf("%s: Exchange succeeded", name)
			}
			if as.tokens.Load() != 0 {
				t.Errorf("%s: a request was sent without a secret", name)
			}
		}
	})
	t.Run("a secret and a secret function together are refused at startup", func(t *testing.T) {
		_, err := oauth.New(silentProvider{}, oauth.Config{
			ClientID: testClient, RedirectURL: "https://app.example/cb", ClientSecret: "a",
			ClientSecretFunc: func(context.Context) (string, error) { return "b", nil },
			Provider:         oauth.Provider{Issuer: testIssuer, AuthURL: "https://idp.example/a", TokenURL: "https://idp.example/t", JWKSURL: "https://idp.example/j"},
		})
		if err == nil {
			t.Fatal("ambiguous secret configuration accepted")
		}
	})
}

// A token with a header-injecting character must not reach the wire.
func TestHostile_Flow_userinfoTokenCannotInjectHeaders(t *testing.T) {
	var got atomic.Value
	srv := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Store(r.Header.Clone())
		_, _ = w.Write([]byte(`{"id":"1"}`))
	}))
	c := userinfoClient(t, srv.URL, nil)
	for name, tok := range map[string]string{"CRLF": "abc\r\nX-Evil: 1", "LF": "abc\nX-Evil: 1", "NUL": "abc\x00def"} {
		if info, err := c.UserInfo(ctx(t), tok); err == nil {
			t.Errorf("%s: a token with control characters was sent: %v", name, info)
		}
	}
	if h, ok := got.Load().(http.Header); ok && h.Get("X-Evil") != "" {
		t.Fatal("a header was injected through the access token")
	}
	if _, err := c.UserInfo(ctx(t), ""); err == nil {
		t.Fatal("an empty bearer token was sent")
	}
}

func contextCancelled() (context.Context, context.CancelFunc) {
	c, cancel := context.WithCancel(context.Background())
	cancel()
	return c, cancel
}
