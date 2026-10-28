package responses_test

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth"
	"github.com/Glyndor/authcore/tests/hostile/oauth/hostiletest"
)

// make a malformed answer count as a success, or turn an error into a login.

// surface is one outbound fetch together with a valid answer for it.
type surface struct {
	name string
	// good is a response body the client accepts.
	good func(t *testing.T, base string) []byte
	// call runs the fetch against base; hc may be nil. It reports the error.
	call func(t *testing.T, base string, hc *http.Client) error
	// refusal is the sentinel the surface fails with when a response is refused.
	refusal error
}

func surfaces() []surface {
	return []surface{
		{
			name:    "exchange",
			refusal: oauth.ErrExchange,
			good: func(*testing.T, string) []byte {
				return []byte(`{"access_token":"at","token_type":"Bearer","id_token":"x.y.z","expires_in":3600}`)
			},
			call: func(t *testing.T, base string, hc *http.Client) error {
				c := hostiletest.TokenClient(t, base+"/token", func(c *oauth.Config) { c.HTTPClient = hc })
				_, err := c.Exchange(hostiletest.Ctx(t), "the-code", "the-verifier")
				return err
			},
		},
		{
			name:    "userinfo",
			refusal: oauth.ErrUserInfo,
			good:    func(*testing.T, string) []byte { return []byte(`{"id":"42","login":"octo"}`) },
			call: func(t *testing.T, base string, hc *http.Client) error {
				c := hostiletest.UserinfoClient(t, base+"/userinfo", func(c *oauth.Config) { c.HTTPClient = hc })
				_, err := c.UserInfo(hostiletest.Ctx(t), "access-token")
				return err
			},
		},
		{
			name:    "jwks",
			refusal: oauth.ErrIDTokenInvalid,
			good:    func(t *testing.T, _ string) []byte { return hostiletest.StdJWKS(t) },
			call: func(t *testing.T, base string, hc *http.Client) error {
				c := hostiletest.OIDCClient(t, base+"/jwks", func(c *oauth.Config) { c.HTTPClient = hc })
				_, err := c.VerifyIDToken(hostiletest.Ctx(t), hostiletest.SignA(t, hostiletest.Claims(hostiletest.Nonce, nil)), hostiletest.Nonce)
				return err
			},
		},
		{
			name:    "discovery",
			refusal: oauth.ErrDiscovery,
			good: func(_ *testing.T, base string) []byte {
				b, _ := json.Marshal(hostiletest.GoodDoc(base))
				return b
			},
			call: func(t *testing.T, base string, hc *http.Client) error {
				_, err := oauth.Discover(hostiletest.Ctx(t), base, hc)
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
