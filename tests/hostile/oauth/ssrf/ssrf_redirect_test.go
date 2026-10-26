package ssrf_test

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/oauth"
	"github.com/Glyndor/authcore/tests/hostile/oauth/hostiletest"
)

// Attacker: a provider (or a man in the middle on a provider's path) that
// answers a request the client makes with a redirect. Effect they want: the
// client follows it to a host it never configured, a plaintext URL, or an
// internal address, replaying the authorization code and the client secret
// (a 307/308 repeats the POST body) or probing the internal network.

// endpoint is one of the four outbound fetches of the client.
type endpoint struct {
	name string
	run  func(t *testing.T, base string, hc *http.Client) error
}

func endpoints() []endpoint {
	return []endpoint{
		{"token exchange", func(t *testing.T, base string, hc *http.Client) error {
			c := hostiletest.TokenClient(t, base+"/token", func(c *oauth.Config) { c.HTTPClient = hc; c.ClientSecret = "s3cr3t-value" })
			_, err := c.Exchange(hostiletest.Ctx(t), "the-code", "the-verifier")
			return err
		}},
		{"jwks", func(t *testing.T, base string, hc *http.Client) error {
			c := hostiletest.OIDCClient(t, base+"/jwks", func(c *oauth.Config) { c.HTTPClient = hc })
			_, err := c.VerifyIDToken(hostiletest.Ctx(t), hostiletest.SignA(t, hostiletest.Claims(hostiletest.Nonce, nil)), hostiletest.Nonce)
			return err
		}},
		{"userinfo", func(t *testing.T, base string, hc *http.Client) error {
			c := hostiletest.UserinfoClient(t, base+"/userinfo", func(c *oauth.Config) { c.HTTPClient = hc })
			_, err := c.UserInfo(hostiletest.Ctx(t), "access-token")
			return err
		}},
		{"discovery", func(t *testing.T, base string, hc *http.Client) error {
			_, err := oauth.Discover(hostiletest.Ctx(t), base, hc)
			return err
		}},
	}
}

// insecureClient trusts any certificate (every server here is local) so that
// a redirect which the library wrongly allows really reaches its target and
// the hit counter proves it.
func insecureClient() *http.Client {
	return &http.Client{
		Timeout:   3 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}}, // #nosec G402 -- local test servers only.
	}
}

// redirectRig serves a source that always answers with status and location,
// next to a second server standing for the attacker's host.
func redirectRig(t *testing.T, status int, location func(srcURL, evilURL string) string) (src, evil *hostiletest.IDP) {
	t.Helper()
	evil, _ = hostiletest.ServeTLS(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	src, _ = hostiletest.ServeTLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, location("https://"+r.Host, evil.URL), status)
	}))
	return src, evil
}

func port(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	return u.Port()
}

func TestHostile_Redirect_leavingTheConfiguredOriginIsRefused(t *testing.T) {
	type row struct {
		name, reason string
		loc          func(src, evil string) string
	}
	rows := []row{
		// A different host name (no DNS needed: "localhost" is a name, not an IP literal).
		{"other host name, same scheme", "cross-origin", func(_, e string) string { return "https://localhost:" + port(e) + "/steal" }},
		{"other host name behind a userinfo decoy", "cross-origin", func(s, e string) string {
			return "https://" + strings.TrimPrefix(s, "https://") + "@localhost:" + port(e) + "/steal"
		}},
		{"scheme-relative location to another host", "cross-origin", func(_, e string) string { return "//localhost:" + port(e) + "/steal" }},
		{"decimal spelling of 127.0.0.1", "cross-origin", func(_, e string) string { return "https://2130706433:" + port(e) + "/steal" }},
		{"short spelling 127.1", "cross-origin", func(_, e string) string { return "https://127.1:" + port(e) + "/steal" }},
		{"octal spelling 0177.0.0.1", "cross-origin", func(_, e string) string { return "https://0177.0.0.1:" + port(e) + "/steal" }},
		{"same host, other port", "private host", func(_, e string) string { return "https://127.0.0.1:" + port(e) + "/steal" }},
		// Literal internal addresses.
		{"IPv6 loopback", "private host", func(_, e string) string { return "https://[::1]:" + port(e) + "/steal" }},
		{"IPv4-mapped IPv6 loopback", "private host", func(_, e string) string { return "https://[::ffff:127.0.0.1]:" + port(e) + "/steal" }},
		{"unspecified address", "private host", func(_, e string) string { return "https://0.0.0.0:" + port(e) + "/steal" }},
		{"unspecified IPv6 address", "private host", func(_, e string) string { return "https://[::]:" + port(e) + "/steal" }},
		{"cloud metadata", "private host", func(_, _ string) string { return "https://169.254.169.254/latest/meta-data/iam/security-credentials/" }},
		{"cloud metadata IPv6", "private host", func(_, _ string) string { return "https://[fd00:ec2::254]/latest/meta-data/" }},
		{"link-local IPv6", "private host", func(_, _ string) string { return "https://[fe80::1]/" }},
		{"RFC1918 10/8", "private host", func(_, _ string) string { return "https://10.0.0.7/admin" }},
		{"RFC1918 172.16/12", "private host", func(_, _ string) string { return "https://172.16.5.5/admin" }},
		{"RFC1918 192.168/16", "private host", func(_, _ string) string { return "https://192.168.1.1/admin" }},
		{"unique-local IPv6", "private host", func(_, _ string) string { return "https://[fd12:3456::1]/admin" }},
		// Plaintext and exotic schemes.
		{"downgrade to plain http on another port", "non-https", func(_, e string) string { return "http://127.0.0.1:" + port(e) + "/steal" }},
		{"downgrade to plain http on the same host", "non-https", func(s, _ string) string { return "http://" + strings.TrimPrefix(s, "https://") + "/steal" }},
		{"ftp", "non-https", func(_, _ string) string { return "ftp://files.example/x" }},
		{"file", "non-https", func(_, _ string) string { return "file:///etc/passwd" }},
		{"javascript", "non-https", func(_, _ string) string { return "javascript:alert(1)" }},
		{"gopher", "non-https", func(_, _ string) string { return "gopher://127.0.0.1:70/_x" }},
	}
	for _, ep := range endpoints() {
		for _, r := range rows {
			// 307 keeps the POST body (and with it the code and the secret); 302 is the common case.
			for _, status := range []int{http.StatusFound, http.StatusTemporaryRedirect} {
				t.Run(fmt.Sprintf("%s/%s/%d", ep.name, r.name, status), func(t *testing.T) {
					t.Parallel()
					src, evil := redirectRig(t, status, r.loc)
					err := ep.run(t, src.URL, insecureClient())
					if err == nil {
						t.Fatal("the redirect was followed to a successful response")
					}
					if !strings.Contains(err.Error(), "refusing") || !strings.Contains(err.Error(), r.reason) {
						t.Fatalf("refused, but not by the redirect policy (want %q): %v", r.reason, err)
					}
					if n := evil.Hits.Load(); n != 0 {
						t.Fatalf("the attacker host received %d request(s)", n)
					}
				})
			}
		}
	}
}

func TestHostile_Redirect_hopCapStopsALoop(t *testing.T) {
	for _, ep := range endpoints() {
		t.Run(ep.name, func(t *testing.T) {
			t.Parallel()
			src, _ := hostiletest.ServeTLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, r.URL.Path, http.StatusFound)
			}))
			err := ep.run(t, named(src.URL), insecureClient())
			if err == nil || !strings.Contains(err.Error(), "too many redirects") {
				t.Fatalf("a self-redirect loop was not cut by the hop cap: %v", err)
			}
			if n := src.Hits.Load(); n > 6 {
				t.Fatalf("the client sent %d requests into a redirect loop", n)
			}
		})
	}
}

func TestHostile_Redirect_aLoopThroughTwoOriginsStillStopsAtTheFirstCrossing(t *testing.T) {
	// ping-pong: A -> A/next -> evil. The same-origin hop is fine, the crossing is not.
	evil, _ := hostiletest.ServeTLS(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	src, _ := hostiletest.ServeTLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/next" {
			http.Redirect(w, r, "https://localhost:"+port(evil.URL)+"/steal", http.StatusFound)
			return
		}
		http.Redirect(w, r, "/next", http.StatusFound)
	}))
	err := endpoints()[0].run(t, named(src.URL), insecureClient())
	if err == nil || !strings.Contains(err.Error(), "cross-origin") {
		t.Fatalf("the crossing on the second hop was not refused: %v", err)
	}
	if evil.Hits.Load() != 0 {
		t.Fatal("the attacker host was reached")
	}
}

func TestHostile_Redirect_controlSameOriginRedirectStillWorks(t *testing.T) {
	// Without this control every refusal above could be a client that refuses everything.
	body := map[string]string{
		"/token":     `{"access_token":"a","token_type":"Bearer","id_token":"x.y.z"}`,
		"/userinfo":  `{"id":"1"}`,
		"/discovery": "",
	}
	t.Run("token exchange", func(t *testing.T) {
		src, _ := hostiletest.ServeTLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/token" {
				http.Redirect(w, r, "/token2", http.StatusFound)
				return
			}
			_, _ = w.Write([]byte(body["/token"]))
		}))
		if err := endpoints()[0].run(t, named(src.URL), insecureClient()); err != nil {
			t.Fatalf("a same-origin redirect was refused: %v", err)
		}
	})
	t.Run("userinfo", func(t *testing.T) {
		src, _ := hostiletest.ServeTLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/userinfo" {
				http.Redirect(w, r, "/userinfo2", http.StatusFound)
				return
			}
			_, _ = w.Write([]byte(body["/userinfo"]))
		}))
		if err := endpoints()[2].run(t, named(src.URL), insecureClient()); err != nil {
			t.Fatalf("a same-origin redirect was refused: %v", err)
		}
	})
	t.Run("explicit default port is the same origin", func(t *testing.T) {
		// https://host and https://host:443 are one origin; the port compare must not flag it.
		src, _ := hostiletest.ServeTLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/userinfo" {
				http.Redirect(w, r, "https://"+r.Host+"/userinfo2", http.StatusFound)
				return
			}
			_, _ = w.Write([]byte(body["/userinfo"]))
		}))
		if err := endpoints()[2].run(t, named(src.URL), insecureClient()); err != nil {
			t.Fatalf("an absolute same-origin redirect was refused: %v", err)
		}
	})
}

// A caller's own CheckRedirect must be able to tighten the policy, never to
// loosen it: the library's rule runs first.
func TestHostile_Redirect_callerCheckRedirectCannotLoosenThePolicy(t *testing.T) {
	evil, _ := hostiletest.ServeTLS(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	src, _ := hostiletest.ServeTLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:"+port(evil.URL)+"/steal", http.StatusTemporaryRedirect)
	}))
	hc := insecureClient()
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return nil } // "follow everything"
	err := endpoints()[0].run(t, src.URL, hc)
	if err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Fatalf("a permissive caller callback re-enabled the downgrade: %v", err)
	}
	if evil.Hits.Load() != 0 {
		t.Fatal("the attacker host was reached")
	}
	// And a restrictive callback is honoured on top of the library's rule.
	src2, _ := hostiletest.ServeTLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	}))
	hc2 := insecureClient()
	hc2.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if err := endpoints()[2].run(t, src2.URL, hc2); err == nil {
		t.Fatal("the caller's refusal of a redirect was ignored")
	}
}

// The caller's http.Client is a template: the library copies it and must not
// alter the original.
func TestHostile_Redirect_theCallersClientIsNotMutated(t *testing.T) {
	hc := &http.Client{}
	_ = endpoints()[3].run(t, "https://127.0.0.1:1", hc)
	if hc.CheckRedirect != nil || hc.Timeout != 0 {
		t.Fatalf("the caller's client was modified: CheckRedirect set=%v timeout=%v", hc.CheckRedirect != nil, hc.Timeout)
	}
}

// Attacker: a user (or a deployment mistake) that controls a configured URL.
func TestHostile_Config_urlsThatMustNotBeAccepted(t *testing.T) {
	base := oauth.Config{
		ClientID: hostiletest.ClientID, RedirectURL: "https://app.example/cb",
		Provider: oauth.Provider{
			Issuer: hostiletest.Issuer, AuthURL: "https://idp.example/auth",
			TokenURL: "https://idp.example/token", JWKSURL: "https://idp.example/jwks",
		},
	}
	type mutation struct {
		field string
		set   func(*oauth.Config, string)
	}
	fields := []mutation{
		{"redirect URL", func(c *oauth.Config, v string) { c.RedirectURL = v }},
		{"auth URL", func(c *oauth.Config, v string) { c.Provider.AuthURL = v }},
		{"token URL", func(c *oauth.Config, v string) { c.Provider.TokenURL = v }},
		{"jwks URL", func(c *oauth.Config, v string) { c.Provider.JWKSURL = v }},
		{"issuer", func(c *oauth.Config, v string) { c.Provider.Issuer = v }},
	}
	bad := map[string]string{
		"plain http to a real host":      "http://idp.example/x",
		"plain http to a metadata host":  "http://169.254.169.254/latest",
		"http with a loopback-like name": "http://localhost.evil.example/x",
		"http with a 127. prefix name":   "http://127.0.0.1.evil.example/x",
		"http userinfo decoy":            "http://localhost@evil.example/x",
		"ftp":                            "ftp://idp.example/x",
		"file":                           "file:///etc/passwd",
		"javascript":                     "javascript:alert(1)",
		"data":                           "data:text/html,x",
		"scheme-relative":                "//idp.example/x",
		"relative path":                  "/x",
		"opaque https":                   "https:idp.example",
		"https without a host":           "https:///x",
		"https with empty authority":     "https://",
		"control character":              "https://idp.example/\n",
		"space in the host":              "https://id p.example/",
		"percent in the host":            "https://idp%2eexample%00/",
		"bad port":                       "https://idp.example:notaport/",
	}
	for _, f := range fields {
		for name, v := range bad {
			t.Run(f.field+"/"+name, func(t *testing.T) {
				t.Parallel()
				cfg := base
				f.set(&cfg, v)
				if _, err := oauth.New(hostiletest.SilentProvider{}, cfg); err == nil {
					t.Fatalf("%s %q was accepted", f.field, v)
				}
			})
		}
	}
	// Controls: the exceptions the library documents.
	for name, v := range map[string]string{
		"https": "https://idp.example/x", "loopback name": "http://localhost:8080/x",
		"loopback v4": "http://127.0.0.1:8080/x", "loopback v4 other": "http://127.0.0.2/x", "loopback v6": "http://[::1]:8080/x",
	} {
		cfg := base
		cfg.Provider.TokenURL = v
		if _, err := oauth.New(hostiletest.SilentProvider{}, cfg); err != nil {
			t.Errorf("control %s: %q refused: %v", name, v, err)
		}
	}
	// A fragment on the authorization URL swallows every parameter we add.
	for _, v := range []string{"https://idp.example/auth#x", "https://idp.example/auth#", "https://idp.example/auth?a=1#frag"} {
		cfg := base
		cfg.Provider.AuthURL = v
		if _, err := oauth.New(hostiletest.SilentProvider{}, cfg); err == nil {
			t.Errorf("auth URL %q with a fragment was accepted", v)
		}
	}
}

// named swaps the IP literal of a local server for the name "localhost". The
// library refuses even a same-origin hop while the host is a loopback literal
// (the plaintext-loopback exception is for development only), so the loop and
// control tests need a host that is a name.
func named(raw string) string { return strings.Replace(raw, "127.0.0.1", "localhost", 1) }
