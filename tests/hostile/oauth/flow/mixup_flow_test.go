package flow_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth"
	"github.com/Glyndor/authcore/tests/hostile/oauth/hostiletest"
)

// Attacker: the operator of a second authorization server that the same
// application also trusts (a "log in with" provider they run, or one they
// compromised). Mix-up attack: a login started with the honest provider H is
// steered so that its callback is handled by the client of the attacker's
// provider X, which sends the code and the verifier to X and hands the
// application whatever X answers. What the attacker wants is an identity
// token minted for H that the client of X accepts, or H's client secret.
//
// The library is one Client per provider, so the defence is in what each
// Client refuses and in what it never shares; the application still has to
// pick the Client by its own record of the login.

const (
	issuerH = "https://honest.example"
	issuerX = "https://attacker.example"
	secretH = "secret-of-the-honest-client"
	secretX = "secret-of-the-attackers-client"
	// kidH is the key id H signs with. X publishes H's public key under the
	// same id, so a token of H passes X's signature check and only the issuer
	// check can refuse it.
	kidH = "h-key"
)

// recordingAS answers every token request with respond() and remembers what
// it was sent.
type recordingAS struct {
	mu      sync.Mutex
	forms   []map[string][]string
	auths   []string
	respond func(form map[string][]string) []byte
}

func (a *recordingAS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	form := map[string][]string(r.PostForm)
	a.mu.Lock()
	a.forms = append(a.forms, form)
	a.auths = append(a.auths, r.Header.Get("Authorization"))
	a.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(a.respond(form))
}

func (a *recordingAS) sawAnywhere(needle string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	blob, _ := json.Marshal(a.forms)
	return strings.Contains(string(blob), needle) || strings.Contains(strings.Join(a.auths, "\n"), needle)
}

// twoProviders returns clients for H and X sharing a client id, a kid and a
// redirect URL: the most confusable arrangement. X's key set also publishes
// H's key, so only the issuer check can tell the two apart.
func twoProviders(t *testing.T, tokenX *recordingAS) (cH, cX *oauth.Client) {
	t.Helper()
	a, b := hostiletest.RSAKeys()
	jwksH := hostiletest.Serve(t, hostiletest.StaticBody(hostiletest.JWKSDoc(hostiletest.RSAJWK(kidH, &a.PublicKey, nil))))
	jwksX := hostiletest.Serve(t, hostiletest.StaticBody(hostiletest.JWKSDoc(hostiletest.RSAJWK(hostiletest.KID, &b.PublicKey, nil), hostiletest.RSAJWK(kidH, &a.PublicKey, nil))))
	asH := hostiletest.Serve(t, &recordingAS{respond: func(map[string][]string) []byte { return []byte(`{}`) }})
	asX := hostiletest.Serve(t, tokenX)
	cH = hostiletest.OIDCClient(t, jwksH.URL, func(c *oauth.Config) {
		c.Provider.Issuer, c.Provider.TokenURL, c.ClientSecret = issuerH, asH.URL, secretH
	})
	cX = hostiletest.OIDCClient(t, jwksX.URL, func(c *oauth.Config) {
		c.Provider.Issuer, c.Provider.TokenURL, c.ClientSecret = issuerX, asX.URL, secretX
	})
	return cH, cX
}

func TestHostile_MixUp_theCallbackOfOneProviderHandledByTheOtherClient(t *testing.T) {
	a, b := hostiletest.RSAKeys()
	hToken := hostiletest.Mint{Key: a, Kid: kidH, Claims: hostiletest.Claims(hostiletest.Nonce, map[string]any{"iss": issuerH, "sub": "victim-at-h"})}.String(t)
	tokenX := &recordingAS{}
	tokenX.respond = func(map[string][]string) []byte {
		// X returns the token H issued for this login (it replays the code to
		// H, with the verifier it was just given).
		out, _ := json.Marshal(map[string]any{"access_token": "at", "token_type": "Bearer", "id_token": hToken})
		return out
	}
	cH, cX := twoProviders(t, tokenX)

	t.Run("control: H's token is accepted by H", func(t *testing.T) {
		got, err := hostiletest.Verify(t, cH, hToken)
		if err != nil || got.Issuer != issuerH || got.Subject != "victim-at-h" {
			t.Fatalf("%+v, %v", got, err)
		}
	})
	t.Run("X's client refuses the token minted for H", func(t *testing.T) {
		tok, err := cX.Exchange(hostiletest.Ctx(t), "code-of-the-honest-login", "verifier-of-the-honest-login")
		if err != nil {
			t.Fatalf("the exchange itself should reach X and return: %v", err)
		}
		got, err := hostiletest.Verify(t, cX, tok.IDToken)
		hostiletest.MustRejectToken(t, got, err)
	})
	t.Run("X's client never reveals H's secret to X", func(t *testing.T) {
		if tokenX.sawAnywhere(secretH) {
			t.Fatal("H's client secret reached X's token endpoint")
		}
		if !tokenX.sawAnywhere(secretX) {
			t.Fatal("control: X's own credentials were not even sent")
		}
	})
	t.Run("a token X really issued carries X's issuer, never H's", func(t *testing.T) {
		own := hostiletest.Mint{Key: b, Claims: hostiletest.Claims(hostiletest.Nonce, map[string]any{"iss": issuerX, "sub": "victim-at-h"})}.String(t)
		got, err := hostiletest.Verify(t, cX, own)
		if err != nil {
			t.Fatalf("control: X's own token refused by X: %v", err)
		}
		if got.Issuer != issuerX || got.Issuer == issuerH {
			t.Fatalf("an identity from X is labelled %q; an application keying on (issuer, subject) would merge it with H's", got.Issuer)
		}
		if h, err := hostiletest.Verify(t, cH, own); err == nil {
			t.Fatalf("H's client accepted X's token: %+v", h)
		}
	})
}

// Two clients hammered at once with each other's tokens: the key caches stay
// separate even though they share a kid and the answers never cross.
func TestHostile_MixUp_keyCachesOfTwoProvidersNeverMix(t *testing.T) {
	a, b := hostiletest.RSAKeys()
	cH, cX := twoProviders(t, &recordingAS{respond: func(map[string][]string) []byte { return nil }})
	tokH := hostiletest.Mint{Key: a, Kid: kidH, Claims: hostiletest.Claims(hostiletest.Nonce, map[string]any{"iss": issuerH})}.String(t)
	tokX := hostiletest.Mint{Key: b, Claims: hostiletest.Claims(hostiletest.Nonce, map[string]any{"iss": issuerX})}.String(t)

	var wg sync.WaitGroup
	var bad sync.Map
	run := func(name string, c *oauth.Client, tok string, want bool) {
		defer wg.Done()
		for range 40 {
			if _, err := c.VerifyIDToken(hostiletest.Ctx(t), tok, hostiletest.Nonce); (err == nil) != want {
				bad.Store(name, err)
			}
		}
	}
	for range 8 {
		wg.Add(4)
		go run("H accepts H", cH, tokH, true)
		go run("H refuses X", cH, tokX, false)
		go run("X accepts X", cX, tokX, true)
		go run("X refuses H", cX, tokH, false)
	}
	wg.Wait()
	bad.Range(func(k, v any) bool {
		t.Errorf("%s: unexpected outcome (%v)", k, v)
		return true
	})
}

// The secrets of two clients live in two token endpoints' logs and nowhere else.
func TestHostile_MixUp_eachClientSendsOnlyItsOwnSecretToItsOwnEndpoint(t *testing.T) {
	asH := &recordingAS{respond: func(map[string][]string) []byte { return []byte(`{}`) }}
	asX := &recordingAS{respond: func(map[string][]string) []byte { return []byte(`{}`) }}
	cH := hostiletest.TokenClient(t, hostiletest.Serve(t, asH).URL, func(c *oauth.Config) { c.ClientSecret = secretH })
	cX := hostiletest.TokenClient(t, hostiletest.Serve(t, asX).URL, func(c *oauth.Config) { c.ClientSecret = secretX })
	for range 20 {
		_, _ = cH.Exchange(hostiletest.Ctx(t), "ch", "vh")
		_, _ = cX.Exchange(hostiletest.Ctx(t), "cx", "vx")
	}
	if asH.sawAnywhere(secretX) || asX.sawAnywhere(secretH) {
		t.Fatal("a secret reached the other provider's endpoint")
	}
	if !asH.sawAnywhere(secretH) || !asX.sawAnywhere(secretX) {
		t.Fatal("control: a client did not send its own secret")
	}
}
