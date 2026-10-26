package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"
)

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
