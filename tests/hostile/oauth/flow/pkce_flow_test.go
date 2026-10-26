package flow_test

import (
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth"
	"github.com/Glyndor/authcore/tests/hostile/oauth/hostiletest"
)

// Attacker: someone who saw the authorization request (a proxy, a browser
// extension, a referrer log) and then gets hold of the authorization code
// (an open redirect, a shared device). A public client has nothing but PKCE
// between them and the tokens, so the question is whether anything they can
// read in the URL lets them produce a verifier the server accepts.

// startLogin plays the first leg against the fake server and returns what the
// attacker can see (the URL's parameters) and what only the browser holds.
func startLogin(t *testing.T, c *oauth.Client, as *fakeAS) (r *oauth.AuthRequest, seen url.Values, code string) {
	t.Helper()
	r, err := c.AuthCodeURL()
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(r.URL)
	if err != nil {
		t.Fatal(err)
	}
	return r, u.Query(), as.authorize(t, r.URL)
}

func s256(v string) string {
	sum := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func TestHostile_PKCE_nothingInTheAuthorizationURLUnlocksTheCode(t *testing.T) {
	c, as := flowRig(t, "", nil) // a public client: PKCE alone
	guesses := map[string]func(r *oauth.AuthRequest, seen url.Values) string{
		"the challenge used as a plain verifier": func(_ *oauth.AuthRequest, s url.Values) string { return s.Get("code_challenge") },
		"the state":                              func(r *oauth.AuthRequest, _ url.Values) string { return r.State },
		"the nonce":                              func(r *oauth.AuthRequest, _ url.Values) string { return r.Nonce },
		"the challenge hashed again":             func(_ *oauth.AuthRequest, s url.Values) string { return s256(s.Get("code_challenge")) },
		"the challenge padded to the RFC length": func(_ *oauth.AuthRequest, s url.Values) string {
			return s.Get("code_challenge") + s.Get("code_challenge")
		},
		"the client id":          func(*oauth.AuthRequest, url.Values) string { return hostiletest.ClientID },
		"state and nonce joined": func(r *oauth.AuthRequest, _ url.Values) string { return r.State + r.Nonce },
	}
	for name, guess := range guesses {
		t.Run(name, func(t *testing.T) {
			r, seen, code := startLogin(t, c, as)
			if tok, err := c.Exchange(hostiletest.Ctx(t), code, guess(r, seen)); err == nil {
				t.Fatalf("an observer of the authorization URL exchanged the code: %+v", tok)
			}
			// The attack burnt the code on the server; a fresh login proves
			// the control: the genuine verifier does work.
			r, _, code = startLogin(t, c, as)
			if _, err := c.Exchange(hostiletest.Ctx(t), code, r.Verifier); err != nil {
				t.Fatalf("control: the genuine verifier was refused: %v", err)
			}
		})
	}
}

func TestHostile_PKCE_aVerifierThatIsNotTheIssuedOneIsRefused(t *testing.T) {
	c, as := flowRig(t, "", nil)
	last := func(v string) byte { return v[len(v)-1] }
	flip := func(v string) string {
		other := byte('A')
		if last(v) == other {
			other = 'B'
		}
		return v[:len(v)-1] + string(other)
	}
	mutations := map[string]func(v string) string{
		"last character changed": flip,
		"truncated by one":       func(v string) string { return v[:len(v)-1] },
		"extended by one":        func(v string) string { return v + "A" },
		"lower-cased":            strings.ToLower,
		"upper-cased":            strings.ToUpper,
		"leading space":          func(v string) string { return " " + v },
		"trailing newline":       func(v string) string { return v + "\n" },
		"trailing NUL":           func(v string) string { return v + "\x00" },
		"standard base64 form":   func(v string) string { return strings.NewReplacer("-", "+", "_", "/").Replace(v) + "=" },
		"reversed": func(v string) string {
			r := []byte(v)
			for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
				r[i], r[j] = r[j], r[i]
			}
			return string(r)
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			r, _, code := startLogin(t, c, as)
			if mutate(r.Verifier) == r.Verifier {
				t.Skip("the mutation left this verifier unchanged")
			}
			if tok, err := c.Exchange(hostiletest.Ctx(t), code, mutate(r.Verifier)); err == nil {
				t.Fatalf("a different verifier was accepted: %+v", tok)
			}
		})
	}
	t.Run("a verifier from a concurrent login", func(t *testing.T) {
		victim, _, code := startLogin(t, c, as)
		other, _, _ := startLogin(t, c, as)
		if victim.Verifier == other.Verifier {
			t.Fatal("two logins share a verifier")
		}
		if tok, err := c.Exchange(hostiletest.Ctx(t), code, other.Verifier); err == nil {
			t.Fatalf("the verifier of another login unlocked this code: %+v", tok)
		}
	})
}

// The library must never offer a way back to "plain": the method on the wire
// is S256 whatever the provider's own URL says, and the verifier is never
// derivable from what the URL shows.
func TestHostile_PKCE_noConfigurationDowngradesTheMethod(t *testing.T) {
	for name, endpoint := range map[string]string{
		"plain preset":     "https://idp.example/auth?code_challenge_method=plain",
		"empty method":     "https://idp.example/auth?code_challenge_method=",
		"lowercase method": "https://idp.example/auth?code_challenge_method=s256",
		"no pkce at all":   "https://idp.example/auth?code_challenge=x",
	} {
		t.Run(name, func(t *testing.T) {
			c := hostiletest.OIDCClient(t, "https://idp.example/jwks", func(cfg *oauth.Config) { cfg.Provider.AuthURL = endpoint })
			for range 20 {
				r, err := c.AuthCodeURL()
				if err != nil {
					t.Fatal(err)
				}
				u, _ := url.Parse(r.URL)
				q := u.Query()
				if q.Get("code_challenge_method") != "S256" || len(q["code_challenge_method"]) != 1 {
					t.Fatalf("method = %q", q["code_challenge_method"])
				}
				if q.Get("code_challenge") != s256(r.Verifier) || q.Get("code_challenge") == r.Verifier {
					t.Fatalf("challenge %q is not S256 of the verifier", q.Get("code_challenge"))
				}
				if len(r.Verifier) < 43 || len(r.Verifier) > 128 {
					t.Fatalf("verifier length %d is outside RFC 7636 section 4.1", len(r.Verifier))
				}
			}
		})
	}
}
