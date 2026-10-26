package flow_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth"
	"github.com/Glyndor/authcore/tests/hostile/oauth/hostiletest"
)

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
		a, _ := hostiletest.RSAKeys()
		idt := hostiletest.Mint{Key: a, Claims: hostiletest.Claims(nonce, nil)}
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
		return uu == hostiletest.ClientID && pp == as.secret
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
	a, _ := hostiletest.RSAKeys()
	redirect := "https://app.example/cb"
	as := newFakeAS(t, secret, redirect)
	asSrv := hostiletest.Serve(t, as)
	jwks := hostiletest.Serve(t, hostiletest.StaticBody(hostiletest.JWKSDoc(hostiletest.RSAJWK(hostiletest.KID, &a.PublicKey, nil))))
	c := hostiletest.OIDCClient(t, jwks.URL, func(c *oauth.Config) {
		c.RedirectURL = redirect
		c.ClientSecret = secret
		c.Provider.TokenURL = asSrv.URL
		if mut != nil {
			mut(c)
		}
	})
	return c, as
}

func contextCancelled() (context.Context, context.CancelFunc) {
	c, cancel := context.WithCancel(context.Background())
	cancel()
	return c, cancel
}
