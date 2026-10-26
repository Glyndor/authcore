package tokenshapes_test

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth"
	"github.com/Glyndor/authcore/tests/hostile/oauth/hostiletest"
)

// Attacker: the provider, or a man in the middle of a misconfigured one,
// answering the token request with a body that is valid JSON and wrong in
// every field a client might lean on. Effect they want: a panic, a login
// that proceeds without an identity token, or a value that turns into
// something else once it leaves the library.

func exchangeBody(t *testing.T, body []byte, mut func(*oauth.Config)) (*oauth.Tokens, error) {
	t.Helper()
	srv := hostiletest.Serve(t, hostiletest.StaticBody(body))
	return hostiletest.TokenClient(t, srv.URL, mut).Exchange(hostiletest.Ctx(t), "code", "verifier")
}

func TestHostile_TokenResponse_everyFieldInEveryWrongShape(t *testing.T) {
	base := func(over map[string]string) []byte {
		f := map[string]string{"access_token": "at", "token_type": "Bearer", "id_token": "h.p.s", "expires_in": "raw:3600"}
		for k, v := range over {
			f[k] = v
		}
		return hostiletest.TokenBody(f)
	}
	huge := strings.Repeat("x", 600<<10) // a long value that still fits under the 1 MiB body cap
	cases := []struct {
		name string
		body []byte
		want error // nil: accepted
	}{
		{"control: well formed", base(nil), nil},
		{"token_type in another case", base(map[string]string{"token_type": "bearer"}), nil},
		{"token_type is an unknown scheme", base(map[string]string{"token_type": "N_A"}), nil},
		{"token_type is a number", base(map[string]string{"token_type": "raw:1"}), oauth.ErrExchange},
		{"token_type is an array", base(map[string]string{"token_type": `raw:["Bearer"]`}), oauth.ErrExchange},
		{"token_type is an object", base(map[string]string{"token_type": `raw:{"a":1}`}), oauth.ErrExchange},
		{"token_type is null", base(map[string]string{"token_type": "raw:null"}), oauth.ErrExchange},
		{"token_type is missing", base(map[string]string{"token_type": ""}), oauth.ErrExchange},
		{"access_token is a number", base(map[string]string{"access_token": "raw:7"}), oauth.ErrExchange},
		{"access_token is null", base(map[string]string{"access_token": "raw:null"}), oauth.ErrExchange},
		{"access_token is missing", base(map[string]string{"access_token": ""}), oauth.ErrExchange},
		{"access_token is an object", base(map[string]string{"access_token": `raw:{"v":"x"}`}), oauth.ErrExchange},
		{"expires_in is a string", base(map[string]string{"expires_in": `raw:"3600"`}), oauth.ErrExchange},
		{"expires_in is fractional", base(map[string]string{"expires_in": "raw:3600.5"}), oauth.ErrExchange},
		{"expires_in overflows int64", base(map[string]string{"expires_in": "raw:99999999999999999999"}), oauth.ErrExchange},
		{"expires_in is exponent notation", base(map[string]string{"expires_in": "raw:1e400"}), oauth.ErrExchange},
		{"expires_in is a boolean", base(map[string]string{"expires_in": "raw:true"}), oauth.ErrExchange},
		{"expires_in is an array", base(map[string]string{"expires_in": "raw:[3600]"}), oauth.ErrExchange},
		{"expires_in is null", base(map[string]string{"expires_in": "raw:null"}), nil},
		{"expires_in is absent", base(map[string]string{"expires_in": ""}), nil},
		{"id_token is missing", base(map[string]string{"id_token": ""}), oauth.ErrNoIDToken},
		{"id_token is null", base(map[string]string{"id_token": "raw:null"}), oauth.ErrNoIDToken},
		{"id_token is an empty string", base(map[string]string{"id_token": "raw:\"\""}), oauth.ErrNoIDToken},
		{"id_token is a number", base(map[string]string{"id_token": "raw:7"}), oauth.ErrExchange},
		{"id_token is an array", base(map[string]string{"id_token": `raw:["a.b.c"]`}), oauth.ErrExchange},
		{"refresh_token is a number", base(map[string]string{"refresh_token": "raw:7"}), oauth.ErrExchange},
		{"values near the body cap", base(map[string]string{"access_token": huge}), nil},
		{"a byte order mark before the object", append([]byte("\xef\xbb\xbf"), base(nil)...), oauth.ErrExchange},
		{"two objects", append(base(nil), base(nil)...), oauth.ErrExchange},
		{"the object followed by junk", append(base(nil), []byte("garbage")...), oauth.ErrExchange},
		{"an array of the object", append(append([]byte("["), base(nil)...), ']'), oauth.ErrExchange},
		{"a bare string", []byte(`"access_token"`), oauth.ErrExchange},
		{"empty body", nil, oauth.ErrExchange},
		{"unknown extra fields", base(map[string]string{"scope": "openid", "ext_expires_in": "raw:7200", "x": `raw:{"deep":[1,2]}`}), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tok, err := exchangeBody(t, tc.body, nil)
			switch {
			case tc.want == nil && err != nil:
				t.Fatalf("refused: %v", err)
			case tc.want != nil && err == nil:
				t.Fatalf("accepted %+v", tok)
			case tc.want != nil && !errors.Is(err, tc.want):
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if err != nil && tok != nil {
				t.Fatalf("an error came with tokens: %+v", tok)
			}
		})
	}
}

// Whatever the provider calls its token, the library presents it as Bearer
// and in one header line: the response's token_type picks nothing.
func TestHostile_TokenResponse_tokenTypeAndTokenNeverReshapeTheNextRequest(t *testing.T) {
	var mu sync.Mutex
	var got http.Header
	profile := hostiletest.Serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = r.Header.Clone()
		mu.Unlock()
		_, _ = w.Write([]byte(`{"id":1}`))
	}))
	for _, tt := range []string{"mac", "None", "Bearer\r\nX-Evil: 1", "Basic dXNlcjpwYXNz"} {
		tokens := hostiletest.Serve(t, hostiletest.StaticBody(hostiletest.TokenBody(map[string]string{"access_token": "at-1", "token_type": tt})))
		c := hostiletest.UserinfoClient(t, profile.URL, func(cfg *oauth.Config) { cfg.Provider.TokenURL = tokens.URL })
		tok, err := c.Exchange(hostiletest.Ctx(t), "code", "verifier")
		if err != nil {
			t.Fatalf("token_type %q: %v", tt, err)
		}
		if _, err := c.UserInfo(hostiletest.Ctx(t), tok.AccessToken); err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		auth, evil := got.Get("Authorization"), got.Get("X-Evil")
		mu.Unlock()
		if auth != "Bearer at-1" || evil != "" {
			t.Fatalf("token_type %q changed the request: Authorization=%q X-Evil=%q", tt, auth, evil)
		}
	}
}

// An id_token that is present but is not a JWT never becomes an identity.
func TestHostile_TokenResponse_anIDTokenThatIsNotAJWTNeverVerifies(t *testing.T) {
	c, _ := hostiletest.JWKSClient(t, hostiletest.StdJWKS(t))
	for _, idt := range []string{" ", "null", "undefined", "Bearer x.y.z", "...", "a.b", "a.b.c.d", "\x00", strings.Repeat(".", 100)} {
		got, err := hostiletest.Verify(t, c, idt)
		hostiletest.MustRejectToken(t, got, err)
	}
}

// The authorization code is the one value an attacker places in the token
// request without the library's help. It travels as a form value, up to the length bound, intact and alone.
func TestHostile_TokenRequest_aHostileCodeArrivesIntactAndAlone(t *testing.T) {
	var mu sync.Mutex
	var form url.Values
	var hdr http.Header
	var lines int
	srv := hostiletest.Serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		mu.Lock()
		form, hdr, lines = r.PostForm, r.Header.Clone(), len(r.PostForm)
		mu.Unlock()
		w.WriteHeader(http.StatusBadRequest)
	}))
	c := hostiletest.TokenClient(t, srv.URL, func(cfg *oauth.Config) { cfg.ClientSecret = "s" })
	for name, code := range map[string]string{
		"crlf header injection": "abc\r\nX-Evil: 1\r\n\r\nGET /admin HTTP/1.1",
		"nul and controls":      "a\x00b\x01\x1f\x7f",
		"unicode":               "código-\U0001F512-\u202e",
		"percent and plus":      "a%2Fb+c%00%zz",
		"form syntax":           "a=b&grant_type=password&client_secret=x",
		"leading and trailing":  "  code\n",
		"at the length bound":   strings.Repeat("c", 8<<10),
	} {
		t.Run(name, func(t *testing.T) {
			_, _ = c.Exchange(hostiletest.Ctx(t), code, "verifier")
			mu.Lock()
			defer mu.Unlock()
			if form.Get("code") != code {
				t.Fatalf("the code arrived altered or cut: %d bytes in, %d out", len(code), len(form.Get("code")))
			}
			if hdr.Get("X-Evil") != "" || lines != 6 {
				t.Fatalf("the code reshaped the request: %d fields, X-Evil=%q", lines, hdr.Get("X-Evil"))
			}
			if form.Get("grant_type") != "authorization_code" || form.Get("client_secret") != "s" {
				t.Fatalf("a form field was overridden: %v", form)
			}
		})
	}
}
