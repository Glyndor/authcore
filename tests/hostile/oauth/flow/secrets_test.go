package flow_test

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth"
	"github.com/Glyndor/authcore/tests/hostile/oauth/hostiletest"
)

func TestHostile_Flow_clientAuthenticationNeverLeaksTheSecret(t *testing.T) {
	const secret = "s3cr3t:with+odd/chars%and space"
	const id = "client:with:colons"
	t.Run("post: the secret is in the body only", func(t *testing.T) {
		c, as := flowRig(t, secret, func(c *oauth.Config) { c.ClientID = id; c.Provider.AuthMethods = []string{"client_secret_post"} })
		as.secret = secret
		r, _ := c.AuthCodeURL()
		_, _ = c.Exchange(hostiletest.Ctx(t), as.authorize(t, r.URL), r.Verifier)
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
		_, _ = c.Exchange(hostiletest.Ctx(t), as.authorize(t, r.URL), r.Verifier)
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
			if _, err := c.Exchange(hostiletest.Ctx(t), "code", "verifier"); err == nil {
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
		if _, err := c.Exchange(hostiletest.Ctx(t), as.authorize(t, r.URL), r.Verifier); err != nil {
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
		log := &hostiletest.CaptureLogger{}
		srv := hostiletest.Serve(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "nope", 400) }))
		cfg := oauth.Config{
			ClientID: hostiletest.ClientID, ClientSecret: secret, RedirectURL: "https://app.example/cb",
			Provider: oauth.Provider{Issuer: hostiletest.Issuer, AuthURL: "https://idp.example/auth", TokenURL: srv.URL, JWKSURL: "https://idp.example/jwks"},
		}
		c, err := oauth.New(hostiletest.SilentProvider{Log: log}, cfg)
		if err != nil {
			t.Fatal(err)
		}
		_, err = c.Exchange(hostiletest.Ctx(t), "the-secret-code", "the-secret-verifier")
		_, _ = c.VerifyIDToken(hostiletest.Ctx(t), "a.b.c", "n")
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
			if _, err := c.Exchange(hostiletest.Ctx(t), "code", "verifier"); !errors.Is(err, oauth.ErrExchange) {
				t.Errorf("%s: Exchange = %v, want ErrExchange", name, err)
			}
			if as.tokens.Load() != 0 {
				t.Errorf("%s: a request was sent without a secret", name)
			}
		}
	})
	t.Run("a secret and a secret function together are refused at startup", func(t *testing.T) {
		_, err := oauth.New(hostiletest.SilentProvider{}, oauth.Config{
			ClientID: hostiletest.ClientID, RedirectURL: "https://app.example/cb", ClientSecret: "a",
			ClientSecretFunc: func(context.Context) (string, error) { return "b", nil },
			Provider:         oauth.Provider{Issuer: hostiletest.Issuer, AuthURL: "https://idp.example/a", TokenURL: "https://idp.example/t", JWKSURL: "https://idp.example/j"},
		})
		if !errors.Is(err, oauth.ErrInvalidConfig) {
			t.Fatalf("ambiguous secret configuration: %v, want ErrInvalidConfig", err)
		}
	})
}

// A token with a header-injecting character must not reach the wire.
func TestHostile_Flow_userinfoTokenCannotInjectHeaders(t *testing.T) {
	var got atomic.Value
	srv := hostiletest.Serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Store(r.Header.Clone())
		_, _ = w.Write([]byte(`{"id":"1"}`))
	}))
	c := hostiletest.UserinfoClient(t, srv.URL, nil)
	for name, tok := range map[string]string{"CRLF": "abc\r\nX-Evil: 1", "LF": "abc\nX-Evil: 1", "NUL": "abc\x00def"} {
		if info, err := c.UserInfo(hostiletest.Ctx(t), tok); err == nil {
			t.Errorf("%s: a token with control characters was sent: %v", name, info)
		}
	}
	if h, ok := got.Load().(http.Header); ok && h.Get("X-Evil") != "" {
		t.Fatal("a header was injected through the access token")
	}
	if _, err := c.UserInfo(hostiletest.Ctx(t), ""); err == nil {
		t.Fatal("an empty bearer token was sent")
	}
}
