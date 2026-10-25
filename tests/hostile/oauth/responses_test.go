package hostile_test

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth"
)

// Attacker: the other end of any of the four outbound fetches (token,
// userinfo, JWKS, discovery) when it is hostile, compromised or replaced by a
// man in the middle. Effect they want: exhaust the client's memory or time,
// make a malformed answer count as a success, or turn an error into a login.

const responseCap = 1 << 20

// surface is one outbound fetch together with a valid answer for it.
type surface struct {
	name string
	// good is a response body the client accepts.
	good func(t *testing.T, base string) []byte
	// call runs the fetch against base; hc may be nil. It reports the error.
	call func(t *testing.T, base string, hc *http.Client) error
}

func surfaces() []surface {
	return []surface{
		{
			name: "exchange",
			good: func(*testing.T, string) []byte {
				return []byte(`{"access_token":"at","token_type":"Bearer","id_token":"x.y.z","expires_in":3600}`)
			},
			call: func(t *testing.T, base string, hc *http.Client) error {
				c := tokenClient(t, base+"/token", func(c *oauth.Config) { c.HTTPClient = hc })
				_, err := c.Exchange(ctx(t), "the-code", "the-verifier")
				return err
			},
		},
		{
			name: "userinfo",
			good: func(*testing.T, string) []byte { return []byte(`{"id":"42","login":"octo"}`) },
			call: func(t *testing.T, base string, hc *http.Client) error {
				c := userinfoClient(t, base+"/userinfo", func(c *oauth.Config) { c.HTTPClient = hc })
				_, err := c.UserInfo(ctx(t), "access-token")
				return err
			},
		},
		{
			name: "jwks",
			good: func(t *testing.T, _ string) []byte { return stdJWKS(t) },
			call: func(t *testing.T, base string, hc *http.Client) error {
				c := oidcClient(t, base+"/jwks", func(c *oauth.Config) { c.HTTPClient = hc })
				_, err := c.VerifyIDToken(ctx(t), signA(t, claims(testNonce, nil)), testNonce)
				return err
			},
		},
		{
			name: "discovery",
			good: func(_ *testing.T, base string) []byte {
				b, _ := json.Marshal(goodDoc(base))
				return b
			},
			call: func(t *testing.T, base string, hc *http.Client) error {
				_, err := oauth.Discover(ctx(t), base, hc)
				return err
			},
		},
	}
}

// padJSON grows a JSON object to exactly total bytes with a string member.
func padJSON(good []byte, total int) []byte {
	trimmed := bytes.TrimRight(good, " \n")
	head := string(trimmed[:len(trimmed)-1]) + `,"pad":"`
	tail := `"}`
	fill := total - len(head) - len(tail)
	if fill < 0 {
		panic("padJSON: object already larger than total")
	}
	return []byte(head + strings.Repeat("a", fill) + tail)
}

var (
	bombOnce sync.Once
	bombGzip []byte
)

// gzipBomb is a small gzip stream that inflates to far more than the cap.
func gzipBomb(good []byte) []byte {
	bombOnce.Do(func() {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		_, _ = zw.Write([]byte(`{"pad":"`))
		chunk := bytes.Repeat([]byte("a"), 1<<20)
		for range 64 {
			_, _ = zw.Write(chunk)
		}
		_, _ = zw.Write([]byte(`"}`))
		_ = zw.Close()
		bombGzip = buf.Bytes()
	})
	_ = good
	return bombGzip
}

// reply describes what the hostile server sends.
type reply struct {
	status  int
	headers map[string]string
	body    func(t *testing.T, s surface, base string) []byte
}

func goodReply(t *testing.T, s surface, base string) []byte { return s.good(t, base) }

func (r reply) handler(t *testing.T, s surface, base *string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		for k, v := range r.headers {
			w.Header().Set(k, v)
		}
		if w.Header().Get("Content-Type") == "" {
			w.Header().Set("Content-Type", "application/json")
		}
		if r.status != 0 {
			w.WriteHeader(r.status)
		}
		body := r.body
		if body == nil {
			body = goodReply
		}
		_, _ = w.Write(body(t, s, *base))
	})
}

func fixed(b string) func(*testing.T, surface, string) []byte {
	return func(*testing.T, surface, string) []byte { return []byte(b) }
}

func TestHostile_Response_malformedOrWrongShapeNeverCountsAsSuccess(t *testing.T) {
	transform := func(f func(good []byte) []byte) func(*testing.T, surface, string) []byte {
		return func(t *testing.T, s surface, base string) []byte { return f(s.good(t, base)) }
	}
	attacks := map[string]reply{
		"truncated mid-document":             {body: transform(func(g []byte) []byte { return g[:len(g)/2] })},
		"truncated one byte short":           {body: transform(func(g []byte) []byte { return g[:len(g)-1] })},
		"trailing garbage":                   {body: transform(func(g []byte) []byte { return append(append([]byte(nil), g...), "garbage"...) })},
		"two documents back to back":         {body: transform(func(g []byte) []byte { return append(append([]byte(nil), g...), g...) })},
		"byte order mark":                    {body: transform(func(g []byte) []byte { return append([]byte("\xef\xbb\xbf"), g...) })},
		"NUL byte appended":                  {body: transform(func(g []byte) []byte { return append(append([]byte(nil), g...), 0) })},
		"html error page with status 200":    {headers: map[string]string{"Content-Type": "text/html"}, body: fixed("<html><body>Sign in</body></html>")},
		"empty body":                         {body: fixed("")},
		"whitespace only":                    {body: fixed(" \n\t ")},
		"top-level array":                    {body: fixed("[]")},
		"top-level array of the object":      {body: transform(func(g []byte) []byte { return append(append([]byte("["), g...), ']') })},
		"top-level null":                     {body: fixed("null")},
		"top-level string":                   {body: fixed(`"access_token"`)},
		"top-level number":                   {body: fixed("1")},
		"top-level bool":                     {body: fixed("true")},
		"empty object":                       {body: fixed("{}")},
		"valid body, status 500":             {status: 500},
		"valid body, status 404":             {status: 404},
		"valid body, status 401":             {status: 401},
		"valid body, status 403":             {status: 403},
		"valid body, status 429":             {status: 429},
		"valid body, status 301 no location": {status: 301},
		"valid body, status 304":             {status: 304},
		"valid body, status 204":             {status: 204},
		"valid body, status 400":             {status: 400},
		"one byte over the size cap": {body: func(t *testing.T, s surface, base string) []byte {
			return padJSON(s.good(t, base), responseCap+1)
		}},
		"gzip bomb": {headers: map[string]string{"Content-Encoding": "gzip"}, body: func(t *testing.T, s surface, base string) []byte {
			return gzipBomb(s.good(t, base))
		}},
		"gzip header over a plain body": {headers: map[string]string{"Content-Encoding": "gzip"}},
		"gzip stream cut off": {headers: map[string]string{"Content-Encoding": "gzip"}, body: func(t *testing.T, s surface, base string) []byte {
			return gzipBomb(nil)[:2048]
		}},
		"double gzip label": {headers: map[string]string{"Content-Encoding": "gzip, gzip"}, body: func(t *testing.T, s surface, base string) []byte {
			return gzipBomb(nil)
		}},
	}
	for _, s := range surfaces() {
		for name, r := range attacks {
			t.Run(s.name+"/"+name, func(t *testing.T) {
				t.Parallel()
				var base string
				srv := serve(t, r.handler(t, s, &base))
				base = srv.URL
				if err := s.call(t, base, nil); err == nil {
					t.Fatalf("a hostile answer was accepted")
				}
			})
		}
	}
}

func TestHostile_Response_controlsTheCapIsExactAndWhitespaceIsFine(t *testing.T) {
	controls := map[string]reply{
		"plain valid answer": {},
		"exactly at the cap": {body: func(t *testing.T, s surface, base string) []byte {
			return padJSON(s.good(t, base), responseCap)
		}},
		"surrounding whitespace": {body: func(t *testing.T, s surface, base string) []byte {
			return append(append([]byte(" \n"), s.good(t, base)...), " \n"...)
		}},
		"gzip, as a normal server does": {headers: map[string]string{"Content-Encoding": "gzip"}, body: func(t *testing.T, s surface, base string) []byte {
			var buf bytes.Buffer
			zw := gzip.NewWriter(&buf)
			_, _ = zw.Write(s.good(t, base))
			_ = zw.Close()
			return buf.Bytes()
		}},
	}
	for _, s := range surfaces() {
		for name, r := range controls {
			t.Run(s.name+"/"+name, func(t *testing.T) {
				t.Parallel()
				var base string
				srv := serve(t, r.handler(t, s, &base))
				base = srv.URL
				if err := s.call(t, base, nil); err != nil {
					t.Fatalf("control answer refused: %v", err)
				}
			})
		}
	}
}

// A 200 that carries an OAuth error must not become a login.
func TestHostile_Response_errorEnvelopeWith200(t *testing.T) {
	t.Run("exchange", func(t *testing.T) {
		for name, body := range map[string]string{
			"plain error":               `{"error":"invalid_grant"}`,
			"error beside valid tokens": `{"error":"invalid_grant","access_token":"a","token_type":"Bearer","id_token":"i.i.i"}`,
			"error null beside tokens":  `{"error":null,"access_token":"a","token_type":"Bearer","id_token":"i.i.i"}`,
			"error number":              `{"error":400,"access_token":"a","token_type":"Bearer","id_token":"i.i.i"}`,
			"error with description":    `{"error":"invalid_client","error_description":"bad secret"}`,
			"error object":              `{"error":{"code":"x"},"access_token":"a","token_type":"Bearer","id_token":"i.i.i"}`,
			"no access token":           `{"token_type":"Bearer","id_token":"i.i.i"}`,
			"empty access token":        `{"access_token":"","token_type":"Bearer","id_token":"i.i.i"}`,
			"access token null":         `{"access_token":null,"token_type":"Bearer","id_token":"i.i.i"}`,
			"access token a number":     `{"access_token":7,"token_type":"Bearer","id_token":"i.i.i"}`,
			"access token an array":     `{"access_token":["a"],"token_type":"Bearer","id_token":"i.i.i"}`,
			"no token type":             `{"access_token":"a","id_token":"i.i.i"}`,
			"empty token type":          `{"access_token":"a","token_type":"","id_token":"i.i.i"}`,
			"expires_in a string":       `{"access_token":"a","token_type":"Bearer","id_token":"i.i.i","expires_in":"3600"}`,
			"expires_in a float":        `{"access_token":"a","token_type":"Bearer","id_token":"i.i.i","expires_in":3600.5}`,
			"expires_in enormous":       `{"access_token":"a","token_type":"Bearer","id_token":"i.i.i","expires_in":99999999999999999999}`,
			"expires_in infinite":       `{"access_token":"a","token_type":"Bearer","id_token":"i.i.i","expires_in":1e999}`,
			"id_token a number":         `{"access_token":"a","token_type":"Bearer","id_token":5}`,
			"id_token an object":        `{"access_token":"a","token_type":"Bearer","id_token":{"a":1}}`,
			"refresh_token an object":   `{"access_token":"a","token_type":"Bearer","id_token":"i.i.i","refresh_token":{}}`,
		} {
			t.Run(name, func(t *testing.T) {
				srv := serve(t, staticBody([]byte(body)))
				c := tokenClient(t, srv.URL+"/token", nil)
				if tok, err := c.Exchange(ctx(t), "code", "verifier"); err == nil {
					t.Fatalf("accepted as %+v", tok)
				}
			})
		}
	})
	t.Run("an OIDC exchange with no id_token is its own error", func(t *testing.T) {
		srv := serve(t, staticBody([]byte(`{"access_token":"a","token_type":"Bearer"}`)))
		c := tokenClient(t, srv.URL+"/token", nil)
		if _, err := c.Exchange(ctx(t), "code", "verifier"); err == nil || !strings.Contains(err.Error(), oauth.ErrNoIDToken.Error()) {
			t.Fatalf("want ErrNoIDToken, got %v", err)
		}
	})
	t.Run("userinfo", func(t *testing.T) {
		for name, body := range map[string]string{
			"error object":           `{"error":"invalid_token"}`,
			"error beside a profile": `{"error":"invalid_token","id":"42"}`,
			"empty object":           `{}`,
			"null":                   `null`,
			"array":                  `[{"id":"42"}]`,
			"trailing junk":          `{"id":"42"}garbage`,
			"second object":          `{"id":"42"}{"id":"43"}`,
		} {
			t.Run(name, func(t *testing.T) {
				srv := serve(t, staticBody([]byte(body)))
				c := userinfoClient(t, srv.URL, nil)
				if info, err := c.UserInfo(ctx(t), "tok"); err == nil {
					t.Fatalf("accepted as %v", info)
				}
			})
		}
	})
	t.Run("jwks", func(t *testing.T) {
		for name, body := range map[string]string{
			"error object":          `{"error":"server_error"}`,
			"empty set":             `{"keys":[]}`,
			"keys null":             `{"keys":null}`,
			"keys a string":         `{"keys":"x"}`,
			"keys an object":        `{"keys":{}}`,
			"keys of numbers":       `{"keys":[1,2]}`,
			"keys of nulls":         `{"keys":[null,null]}`,
			"keys of empty objects": `{"keys":[{},{}]}`,
			"top-level array":       `[]`,
		} {
			t.Run(name, func(t *testing.T) {
				c, _ := jwksClient(t, []byte(body))
				got, err := verify(t, c, signA(t, claims(testNonce, nil)))
				mustRejectToken(t, got, err)
			})
		}
	})
}

// Numbers that do not fit a float64 must survive a userinfo round trip exactly:
// an id that collapses onto its neighbour merges two accounts.
func TestHostile_Response_userinfoLargeNumbersStayExact(t *testing.T) {
	srv := serve(t, staticBody([]byte(`{"id":9007199254740993,"big":1e999999,"neg":-9223372036854775809,"frac":0.1000000000000000055511151231257827}`)))
	c := userinfoClient(t, srv.URL, nil)
	info, err := c.UserInfo(ctx(t), "tok")
	if err != nil {
		t.Fatalf("UserInfo: %v", err)
	}
	for k, want := range map[string]string{"id": "9007199254740993", "big": "1e999999", "neg": "-9223372036854775809"} {
		n, ok := info[k].(json.Number)
		if !ok || n.String() != want {
			t.Errorf("%s = %#v, want json.Number %s", k, info[k], want)
		}
	}
}

func TestHostile_Response_deeplyNestedJSONIsRefusedWithoutBlowingTheStack(t *testing.T) {
	// 100k levels fit under the 1 MiB cap. The decoder must stop long before the stack does.
	nestedArray := strings.Repeat("[", 100000) + strings.Repeat("]", 100000)
	nestedObject := strings.Repeat(`{"a":`, 100000) + "1" + strings.Repeat("}", 100000)
	bodies := map[string]func(good string) string{
		"nested arrays as an unused member":  func(g string) string { return g[:len(g)-1] + `,"x":` + nestedArray + "}" },
		"nested objects as an unused member": func(g string) string { return g[:len(g)-1] + `,"x":` + nestedObject + "}" },
		"nested arrays at the root":          func(string) string { return nestedArray },
		"nested objects at the root":         func(string) string { return nestedObject },
	}
	for _, s := range surfaces() {
		for name, f := range bodies {
			t.Run(s.name+"/"+name, func(t *testing.T) {
				t.Parallel()
				var base string
				srv := serve(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					_, _ = w.Write([]byte(f(string(s.good(t, base)))))
				}))
				base = srv.URL
				if err := s.call(t, base, nil); err == nil {
					t.Fatal("a document nested 100000 levels deep was accepted")
				}
			})
		}
	}
}
