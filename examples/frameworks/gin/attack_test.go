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
)

// reply is one recorded response.
type reply struct {
	code   int
	header http.Header
	body   string
}

// send drives h with one request. headers are set verbatim, so a test can send
// the same header twice or a value no client library would produce.
func send(t *testing.T, h http.Handler, method, path, body string, headers http.Header) reply {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for name, values := range headers {
		req.Header[name] = values
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	out, _ := io.ReadAll(rec.Result().Body)
	return reply{code: rec.Code, header: rec.Header(), body: string(out)}
}

func authHeader(values ...string) http.Header {
	return http.Header{"Authorization": values}
}

// session registers readmeEmail and logs in, returning both tokens.
func session(t *testing.T, h http.Handler) (access, refresh string) {
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
	h := newEngine(t)
	access, _ := session(t, h)
	huge := strings.Repeat("A", 200<<10)

	cases := []struct {
		name   string
		header http.Header
		want   int
	}{
		{"canonical", authHeader("Bearer " + access), http.StatusOK},
		{"lower-case scheme", authHeader("bearer " + access), http.StatusOK},
		{"upper-case scheme", authHeader("BEARER " + access), http.StatusOK},
		{"scheme only", authHeader("Bearer"), http.StatusUnauthorized},
		{"scheme and space", authHeader("Bearer "), http.StatusUnauthorized},
		{"double space", authHeader("Bearer  " + access), http.StatusUnauthorized},
		{"tab separator", authHeader("Bearer\t" + access), http.StatusUnauthorized},
		{"trailing space", authHeader("Bearer " + access + " "), http.StatusUnauthorized},
		{"trailing word", authHeader("Bearer " + access + " extra"), http.StatusUnauthorized},
		{"other scheme", authHeader("Basic " + access), http.StatusUnauthorized},
		{"no scheme", authHeader(access), http.StatusUnauthorized},
		{"huge token", authHeader("Bearer " + huge), http.StatusUnauthorized},
		{"valid then garbage", authHeader("Bearer "+access, "Bearer garbage"), http.StatusUnauthorized},
		{"garbage then valid", authHeader("Bearer garbage", "Bearer "+access), http.StatusUnauthorized},
		{"valid twice", authHeader("Bearer "+access, "Bearer "+access), http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := send(t, h, http.MethodGet, "/me", "", tc.header)
			if r.code != tc.want {
				t.Errorf("status %d, want %d", r.code, tc.want)
			}
		})
	}
}

// TestForgedTokensAreRefused covers the token swaps and forgeries every JWT
// consumer is tried with.
func TestForgedTokensAreRefused(t *testing.T) {
	h := newEngine(t)
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
		h := newEngine(t)
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
