package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gofiber/fiber/v3"
)

// reply is one recorded response.
type reply struct {
	code   int
	header http.Header
	body   string
}

// send drives app with one request. headers are set verbatim, so a test can
// send the same header twice or a value no client library would produce.
func send(t *testing.T, app *fiber.App, method, path, body string, headers http.Header) reply {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for name, values := range headers {
		req.Header[name] = values
	}
	// Timeout 0 disables app.Test's one-second default: Argon2id under the
	// race detector takes longer than that on a loaded machine.
	resp, err := app.Test(req, fiber.TestConfig{Timeout: 0})
	if err != nil {
		// app.Test returns the limit errors of fasthttp as errors, where a
		// listening server answers them with these statuses.
		switch {
		case strings.Contains(err.Error(), "body size exceeds"):
			return reply{code: http.StatusRequestEntityTooLarge}
		case strings.Contains(err.Error(), "small read buffer"):
			return reply{code: http.StatusRequestHeaderFieldsTooLarge}
		}
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return reply{code: resp.StatusCode, header: resp.Header, body: string(out)}
}

func authHeader(values ...string) http.Header {
	return http.Header{"Authorization": values}
}

// session registers readmeEmail and logs in, returning both tokens.
func session(t *testing.T, h *fiber.App) (access, refresh string) {
	t.Helper()
	if r := send(t, h, http.MethodPost, "/register", credentials(readmeEmail, readmePassword), nil); r.code != http.StatusCreated {
		t.Fatalf("register: status %d", r.code)
	}
	r := send(t, h, http.MethodPost, "/login", credentials(readmeEmail, readmePassword), nil)
	if r.code != http.StatusOK {
		t.Fatalf("login: status %d", r.code)
	}
	var tokens map[string]any
	if err := json.Unmarshal([]byte(r.body), &tokens); err != nil {
		t.Fatalf("login: %v", err)
	}
	return text(tokens, "access_token"), text(tokens, "refresh_token")
}

// TestAuthorizationHeaderForms feeds /me every shape of Authorization header
// an attacker or a sloppy client can produce. Only a single well-formed Bearer
// header may authenticate; everything else is a 401, never a 5xx.
func TestAuthorizationHeaderForms(t *testing.T) {
	h := newTestApp(t)
	access, _ := session(t, h)
	huge := strings.Repeat("A", 200<<10)

	cases := []struct {
		name   string
		header http.Header
		want   int
		alt    int // also acceptable: fasthttp answers 431 to an oversized header
	}{
		{"canonical", authHeader("Bearer " + access), http.StatusOK, 0},
		{"lower-case scheme", authHeader("bearer " + access), http.StatusOK, 0},
		{"upper-case scheme", authHeader("BEARER " + access), http.StatusOK, 0},
		{"scheme only", authHeader("Bearer"), http.StatusUnauthorized, 0},
		{"scheme and space", authHeader("Bearer "), http.StatusUnauthorized, 0},
		{"double space", authHeader("Bearer  " + access), http.StatusUnauthorized, 0},
		{"tab separator", authHeader("Bearer\t" + access), http.StatusUnauthorized, 0},
		{"trailing space", authHeader("Bearer " + access + " "), http.StatusOK, http.StatusUnauthorized}, // fasthttp trims it
		{"trailing word", authHeader("Bearer " + access + " extra"), http.StatusUnauthorized, 0},
		{"other scheme", authHeader("Basic " + access), http.StatusUnauthorized, 0},
		{"no scheme", authHeader(access), http.StatusUnauthorized, 0},
		{"huge token", authHeader("Bearer " + huge), http.StatusUnauthorized, http.StatusRequestHeaderFieldsTooLarge},
		{"valid then garbage", authHeader("Bearer "+access, "Bearer garbage"), http.StatusUnauthorized, 0},
		{"garbage then valid", authHeader("Bearer garbage", "Bearer "+access), http.StatusUnauthorized, 0},
		{"valid twice", authHeader("Bearer "+access, "Bearer "+access), http.StatusUnauthorized, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := send(t, h, http.MethodGet, "/me", "", tc.header)
			if r.code != tc.want && (tc.alt == 0 || r.code != tc.alt) {
				t.Errorf("status %d, want %d", r.code, tc.want)
			}
		})
	}
}

// TestForgedTokensAreRefused covers the token swaps and forgeries every JWT
// consumer is tried with.
func TestForgedTokensAreRefused(t *testing.T) {
	h := newTestApp(t)
	access, refresh := session(t, h)

	enc := base64.RawURLEncoding.EncodeToString
	none := enc([]byte(`{"alg":"none","typ":"JWT"}`)) + "." +
		enc([]byte(`{"sub":"019600ab-1234-7000-8000-000000000001","email":"root@example.com"}`)) + "."

	t.Run("alg none on /me", func(t *testing.T) {
		if r := send(t, h, http.MethodGet, "/me", "", authHeader("Bearer "+none)); r.code != http.StatusUnauthorized {
			t.Errorf("status %d, want 401", r.code)
		}
	})
	t.Run("refresh token on /me", func(t *testing.T) {
		if r := send(t, h, http.MethodGet, "/me", "", authHeader("Bearer "+refresh)); r.code != http.StatusUnauthorized {
			t.Errorf("status %d, want 401", r.code)
		}
	})
	t.Run("access token on /refresh", func(t *testing.T) {
		r := send(t, h, http.MethodPost, "/refresh", refreshBody(access), nil)
		if r.code != http.StatusUnauthorized {
			t.Errorf("status %d, want 401", r.code)
		}
	})
	t.Run("alg none on /refresh", func(t *testing.T) {
		r := send(t, h, http.MethodPost, "/refresh", refreshBody(none), nil)
		if r.code != http.StatusUnauthorized {
			t.Errorf("status %d, want 401", r.code)
		}
	})
	t.Run("every refusal reads the same", func(t *testing.T) {
		var seen string
		for _, tok := range []string{"x", access, none, "a.b.c"} {
			r := send(t, h, http.MethodPost, "/refresh", refreshBody(tok), nil)
			if r.code != http.StatusUnauthorized {
				t.Fatalf("status %d, want 401", r.code)
			}
			if seen != "" && r.body != seen {
				t.Errorf("refusals differ: %q and %q", seen, r.body)
			}
			seen = r.body
		}
	})
}

// TestExpiredRefreshReadsLikeUnknown moves the clock past every lifetime. The
// stored hash still matches, so the failure comes from the token itself, and
// it must read exactly like a token the server never issued.
func TestExpiredRefreshReadsLikeUnknown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newTestApp(t)
		access, refresh := session(t, h)
		unknown := send(t, h, http.MethodPost, "/refresh", refreshBody("x"), nil)

		time.Sleep(400 * 24 * time.Hour)

		expired := send(t, h, http.MethodPost, "/refresh", refreshBody(refresh), nil)
		if expired.code != http.StatusUnauthorized || expired.body != unknown.body {
			t.Errorf("expired refresh token: %d %q, unknown: %d %q", expired.code, expired.body, unknown.code, unknown.body)
		}
		if r := send(t, h, http.MethodGet, "/me", "", authHeader("Bearer "+access)); r.code != http.StatusUnauthorized {
			t.Errorf("expired access token: status %d, want 401", r.code)
		}
	})
}

// TestBodiesAreBounded sends a body far over any legitimate size, and a deeply
// nested one, to every route that reads JSON.
func TestBodiesAreBounded(t *testing.T) {
	h := newTestApp(t)
	big := `{"email":"a@example.com","password":"` + strings.Repeat("x", 1<<20) + `"}`
	nested := strings.Repeat("[", 8000)

	for _, path := range []string{"/register", "/login", "/refresh"} {
		t.Run(path+" oversized", func(t *testing.T) {
			if r := send(t, h, http.MethodPost, path, big, nil); r.code != http.StatusRequestEntityTooLarge {
				t.Errorf("status %d, want 413", r.code)
			}
		})
		t.Run(path+" nested", func(t *testing.T) {
			if r := send(t, h, http.MethodPost, path, nested, nil); r.code != http.StatusBadRequest {
				t.Errorf("status %d, want 400", r.code)
			}
		})
	}
}

// TestMalformedBodiesAreAnswered feeds JSON the handlers do not expect. The
// answer is a plain 400 or 401, with a message that does not echo the decoder.
func TestMalformedBodiesAreAnswered(t *testing.T) {
	h := newTestApp(t)
	bodies := []string{
		``, `null`, `[]`, `"x"`, `{`, `{"email":1,"password":2}`,
		`{"email":["a"],"password":{"b":1}}`,
		`{"email":"a@example.com","email":"b@example.com","password":"Str0ng-P@ssword!"}`,
	}
	for _, path := range []string{"/register", "/login", "/refresh"} {
		for _, body := range bodies {
			r := send(t, h, http.MethodPost, path, body, nil)
			if r.code >= 500 {
				t.Errorf("%s %q: status %d", path, body, r.code)
			}
			for _, leak := range []string{"unmarshal", "cannot", "json:", "EOF", "Field validation", "Go struct"} {
				if strings.Contains(r.body, leak) {
					t.Errorf("%s %q: response echoes decoder detail %q", path, body, leak)
				}
			}
		}
	}
}

// TestRegisterIgnoresInjectedFields tries to choose the subject, the stored
// hashes and a role by adding fields the API never declared.
func TestRegisterIgnoresInjectedFields(t *testing.T) {
	h := newTestApp(t)
	const chosen = "019600ab-1234-7000-8000-000000000001"
	body := `{"email":"` + readmeEmail + `","password":"` + readmePassword + `",` +
		`"id":"` + chosen + `","user_id":"` + chosen + `","role":"admin","admin":true,` +
		`"passwordHash":"x","refreshHash":"y","Extra":{"Email":"root@example.com"}}`
	if r := send(t, h, http.MethodPost, "/register", body, nil); r.code != http.StatusCreated {
		t.Fatalf("register: status %d", r.code)
	}
	r := send(t, h, http.MethodPost, "/login", credentials(readmeEmail, readmePassword), nil)
	var tokens map[string]any
	_ = json.Unmarshal([]byte(r.body), &tokens)

	me := send(t, h, http.MethodGet, "/me", "", authHeader("Bearer "+text(tokens, "access_token")))
	var claims map[string]any
	_ = json.Unmarshal([]byte(me.body), &claims)
	if text(claims, "user_id") == chosen {
		t.Error("the caller chose the account id")
	}
	if text(claims, "email") != readmeEmail {
		t.Errorf("email %q, want %q", text(claims, "email"), readmeEmail)
	}
	if strings.Contains(me.body, "admin") {
		t.Error("an injected role reached the claims")
	}
}

// TestUnexpectedRoutesAndMethods checks that nothing but the four documented
// routes answers, and that a wrong method never reaches a handler.
func TestUnexpectedRoutesAndMethods(t *testing.T) {
	h := newTestApp(t)
	cases := []struct{ method, path string }{
		{http.MethodGet, "/login"}, {http.MethodPut, "/register"}, {http.MethodDelete, "/refresh"},
		{http.MethodPost, "/me"}, {http.MethodGet, "/admin"}, {http.MethodGet, "/debug/pprof/"},
		{http.MethodGet, "/.env"}, {http.MethodTrace, "/me"},
	}
	for _, tc := range cases {
		r := send(t, h, tc.method, tc.path, "", nil)
		if r.code != http.StatusNotFound && r.code != http.StatusMethodNotAllowed && r.code != http.StatusUnauthorized {
			t.Errorf("%s %s: status %d", tc.method, tc.path, r.code)
		}
		if r.code == http.StatusOK {
			t.Errorf("%s %s answered 200", tc.method, tc.path)
		}
	}
}

// TestTokenResponsesAreNotCacheable requires no-store on every response, the
// token-bearing ones above all.
func TestTokenResponsesAreNotCacheable(t *testing.T) {
	h := newTestApp(t)
	send(t, h, http.MethodPost, "/register", credentials(readmeEmail, readmePassword), nil)
	for _, path := range []string{"/login", "/register"} {
		r := send(t, h, http.MethodPost, path, credentials(readmeEmail, readmePassword), nil)
		if got := r.header.Get("Cache-Control"); got != "no-store" {
			t.Errorf("%s: Cache-Control %q, want no-store", path, got)
		}
		if got := r.header.Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("%s: X-Content-Type-Options %q, want nosniff", path, got)
		}
	}
}

// TestServerHasTimeouts guards the slow-client defences of the app main
// serves.
func TestServerHasTimeouts(t *testing.T) {
	cfg := newTestApp(t).Config()
	if cfg.ReadTimeout <= 0 || cfg.WriteTimeout <= 0 || cfg.IdleTimeout <= 0 {
		t.Errorf("a server timeout is unset: read %v write %v idle %v", cfg.ReadTimeout, cfg.WriteTimeout, cfg.IdleTimeout)
	}
	if cfg.BodyLimit <= 0 || cfg.BodyLimit > 64<<10 {
		t.Errorf("BodyLimit %d is not a small explicit bound", cfg.BodyLimit)
	}
}

// TestPanicDoesNotReachTheClient adds a route that panics with an internal
// message after the app was built. The process must survive, and the message
// must stay out of the response.
func TestPanicDoesNotReachTheClient(t *testing.T) {
	app := newTestApp(t)
	app.Get("/boom", func(fiber.Ctx) error { panic("db password is hunter2") })

	r := send(t, app, http.MethodGet, "/boom", "", nil)
	if r.code != http.StatusInternalServerError {
		t.Errorf("status %d, want 500", r.code)
	}
	if strings.Contains(r.body, "hunter2") || strings.Contains(r.body, "db password") {
		t.Error("the panic message reached the client")
	}
}

// TestEmptyRefreshTokenIsABadBody checks the one required field every route
// of the API shares: a refresh request with no token never reaches a lookup.
func TestEmptyRefreshTokenIsABadBody(t *testing.T) {
	h := newTestApp(t)
	for _, body := range []string{`{}`, `{"refresh_token":""}`, `{"refresh_token":null}`} {
		if r := send(t, h, http.MethodPost, "/refresh", body, nil); r.code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", body, r.code)
		}
	}
}
