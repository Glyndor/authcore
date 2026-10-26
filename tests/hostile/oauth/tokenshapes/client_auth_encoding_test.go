package tokenshapes_test

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth"
	"github.com/Glyndor/authcore/tests/hostile/oauth/hostiletest"
)

// Attacker: nobody in particular. A client id or secret that holds a colon,
// a plus, a percent sign or a non-ASCII letter must reach a compliant token
// endpoint as the same string it was configured as; if it does not, the
// login fails for one customer and, worse, a colon in an id lets the id and
// the secret be split in the wrong place. RFC 6749 section 2.3.1 form-encodes
// both values before the Basic header joins them.

// credentialsOnTheWire is what a compliant token endpoint reads back.
type credentialsOnTheWire struct {
	mu                  sync.Mutex
	id, secret, headers string
	bodySecret          string
	bodyID              string
	hadAuthorization    bool
	err                 string
}

func (w *credentialsOnTheWire) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	w.mu.Lock()
	defer w.mu.Unlock()
	w.bodySecret, w.bodyID = r.PostForm.Get("client_secret"), r.PostForm.Get("client_id")
	w.err = ""
	raw := r.Header.Get("Authorization")
	w.hadAuthorization = raw != ""
	if raw != "" {
		w.headers = raw
		dec, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(raw, "Basic "))
		if err != nil {
			w.err = "not base64: " + err.Error()
		} else {
			rawID, rawSecret, _ := strings.Cut(string(dec), ":")
			w.id, _ = url.QueryUnescape(rawID)
			w.secret, _ = url.QueryUnescape(rawSecret)
		}
	}
	rw.WriteHeader(http.StatusBadRequest)
}

var awkward = map[string]string{
	"plain":              "s3cr3t",
	"space":              "with space",
	"plus":               "plus+sign",
	"percent":            "percent%25and%zz",
	"colon":              "colon:inside:twice",
	"unicode":            "é ü 日本語 ß",
	"emoji":              "lock\U0001F512",
	"control characters": "cr\r\nlf\ttab\x01",
	"nul":                "nul\x00byte",
	"quotes":             `quote"'back` + "`",
	"reserved":           "~*()!$,;@[]{}|^<>",
	"form syntax":        "=&?#",
	"backslash":          `back\slash/`,
	"leading space":      "  padded  ",
	"eight kilobytes":    strings.Repeat("k", 8<<10),
}

func TestHostile_ClientAuth_basicEncodingRoundTripsEveryAwkwardCharacter(t *testing.T) {
	for name, value := range awkward {
		t.Run(name, func(t *testing.T) {
			wire := &credentialsOnTheWire{}
			srv := hostiletest.Serve(t, wire)
			c := hostiletest.TokenClient(t, srv.URL, func(cfg *oauth.Config) {
				cfg.ClientID, cfg.ClientSecret = "id:"+value, value
				cfg.Provider.AuthMethods = []string{"client_secret_basic"}
			})
			if _, err := c.Exchange(hostiletest.Ctx(t), "code", "verifier"); err == nil {
				t.Fatal("control: the fake endpoint answers 400, so the exchange must fail")
			}
			wire.mu.Lock()
			defer wire.mu.Unlock()
			if wire.err != "" || !strings.HasPrefix(wire.headers, "Basic ") {
				t.Fatalf("no usable Basic header: %q %s", wire.headers, wire.err)
			}
			if strings.ContainsAny(wire.headers, "\r\n") {
				t.Fatal("the Authorization header spans lines")
			}
			if wire.id != "id:"+value || wire.secret != value {
				t.Fatalf("a compliant server read id=%q secret=%q (lengths %d, %d), want the configured values (%d, %d)",
					clip(wire.id), clip(wire.secret), len(wire.id), len(wire.secret), len("id:"+value), len(value))
			}
			if wire.bodySecret != "" {
				t.Fatal("the secret is also in the body")
			}
		})
	}
}

func TestHostile_ClientAuth_postEncodingRoundTripsEveryAwkwardCharacter(t *testing.T) {
	for name, value := range awkward {
		t.Run(name, func(t *testing.T) {
			wire := &credentialsOnTheWire{}
			srv := hostiletest.Serve(t, wire)
			c := hostiletest.TokenClient(t, srv.URL, func(cfg *oauth.Config) {
				cfg.ClientID = "id:" + value
				cfg.ClientSecretFunc = func(context.Context) (string, error) { return value, nil }
				cfg.Provider.AuthMethods = []string{"client_secret_post"}
			})
			_, _ = c.Exchange(hostiletest.Ctx(t), "code", "verifier")
			wire.mu.Lock()
			defer wire.mu.Unlock()
			if wire.bodySecret != value || wire.bodyID != "id:"+value {
				t.Fatalf("a compliant server read id=%q secret=%q (lengths %d, %d)", clip(wire.bodyID), clip(wire.bodySecret), len(wire.bodyID), len(wire.bodySecret))
			}
			if wire.hadAuthorization {
				t.Fatal("the secret also travelled in an Authorization header")
			}
		})
	}
}

// With a colon in the id the unescaped join would hand the server a shorter
// id and a longer secret: this is the property, stated against the raw bytes.
func TestHostile_ClientAuth_aColonInTheClientIDDoesNotMoveTheSplit(t *testing.T) {
	wire := &credentialsOnTheWire{}
	srv := hostiletest.Serve(t, wire)
	c := hostiletest.TokenClient(t, srv.URL, func(cfg *oauth.Config) {
		cfg.ClientID, cfg.ClientSecret = "tenant:app", "pw"
		cfg.Provider.AuthMethods = []string{"client_secret_basic"}
	})
	_, _ = c.Exchange(hostiletest.Ctx(t), "code", "verifier")
	raw, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(wire.headers, "Basic "))
	if strings.Count(string(raw), ":") != 1 {
		t.Fatalf("the decoded credentials %q hold %d colons; only the separator may remain", raw, strings.Count(string(raw), ":"))
	}
}

func clip(s string) string {
	if len(s) > 40 {
		return s[:40] + "..."
	}
	return s
}
