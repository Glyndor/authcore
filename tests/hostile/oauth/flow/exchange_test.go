package flow_test

import (
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth"
	"github.com/Glyndor/authcore/tests/hostile/oauth/hostiletest"
)

func TestHostile_Flow_attacksOnTheCodeExchange(t *testing.T) {
	t.Run("a verifier from another login is refused by the server", func(t *testing.T) {
		c, as := flowRig(t, "s3cr3t", nil)
		victim, _ := c.AuthCodeURL()
		attacker, _ := c.AuthCodeURL()
		code := as.authorize(t, victim.URL)
		if tok, err := c.Exchange(hostiletest.Ctx(t), code, attacker.Verifier); err == nil {
			t.Fatalf("a code was exchanged with someone else's verifier: %+v", tok)
		}
	})
	t.Run("a code cannot be exchanged twice", func(t *testing.T) {
		c, as := flowRig(t, "s3cr3t", nil)
		r, _ := c.AuthCodeURL()
		code := as.authorize(t, r.URL)
		if _, err := c.Exchange(hostiletest.Ctx(t), code, r.Verifier); err != nil {
			t.Fatalf("control: first exchange failed: %v", err)
		}
		if tok, err := c.Exchange(hostiletest.Ctx(t), code, r.Verifier); err == nil {
			t.Fatalf("a replayed code produced tokens: %+v", tok)
		}
	})
	t.Run("a token from another login fails the nonce check", func(t *testing.T) {
		c, as := flowRig(t, "s3cr3t", nil)
		victim, _ := c.AuthCodeURL()
		attacker, _ := c.AuthCodeURL()
		tok, err := c.Exchange(hostiletest.Ctx(t), as.authorize(t, victim.URL), victim.Verifier)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := c.VerifyIDToken(hostiletest.Ctx(t), tok.IDToken, attacker.Nonce); err == nil {
			t.Fatalf("the victim's token was accepted for the attacker's login: %+v", got)
		}
	})
	t.Run("empty code or verifier never reaches the server", func(t *testing.T) {
		c, as := flowRig(t, "s3cr3t", nil)
		for _, args := range [][2]string{{"", "v"}, {"c", ""}, {"", ""}} {
			if _, err := c.Exchange(hostiletest.Ctx(t), args[0], args[1]); err == nil {
				t.Errorf("Exchange(%q, %q) succeeded", args[0], args[1])
			}
		}
		if n := as.tokens.Load(); n != 0 {
			t.Fatalf("%d requests reached the token endpoint", n)
		}
	})
	t.Run("a failed exchange is not retried", func(t *testing.T) {
		var hits atomic.Int64
		srv := hostiletest.Serve(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			hits.Add(1)
			http.Error(w, "down", http.StatusServiceUnavailable)
		}))
		c := hostiletest.TokenClient(t, srv.URL, func(c *oauth.Config) { c.ClientSecret = "s3cr3t" })
		if _, err := c.Exchange(hostiletest.Ctx(t), "code", "verifier"); err == nil {
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
		if _, err := c.Exchange(hostiletest.Ctx(t), code+"&redirect_uri=https://evil.example", r.Verifier); err == nil {
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
	_, _ = c.Exchange(hostiletest.Ctx(t), code, verifier)
	for _, k := range []string{"grant_type", "client_id", "redirect_uri", "client_secret"} {
		if len(as.lastRaw[k]) != 1 {
			t.Errorf("%s appears %d times on the wire", k, len(as.lastRaw[k]))
		}
	}
	if as.lastRaw.Get("grant_type") != "authorization_code" || as.lastRaw.Get("client_id") != hostiletest.ClientID {
		t.Errorf("a parameter was overridden: %v", as.lastRaw)
	}
	if as.lastRaw.Get("code") != code || as.lastRaw.Get("code_verifier") != verifier {
		t.Errorf("code or verifier altered on the wire: %q %q", as.lastRaw.Get("code"), as.lastRaw.Get("code_verifier"))
	}
	if as.lastRaw.Has("username") {
		t.Error("an injected parameter reached the server")
	}
}
