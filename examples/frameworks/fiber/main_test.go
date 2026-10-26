package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/Glyndor/authcore"
	"github.com/gofiber/fiber/v3"
)

const (
	readmeEmail    = "ana@example.com"
	readmePassword = "Str0ng-P@ssword!"
)

var uuidV7 = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// TestMain serves one request before any test runs. On its first response
// fasthttp started a goroutine that refreshes the Date header forever, and when
// that first response happened inside a synctest bubble the bubble never
// finished: "main bubble goroutine has exited but blocked goroutines remain"
// (fasthttp v1.73.0). Keep this warm-up outside every bubble.
func TestMain(m *testing.M) {
	warmUp := fiber.New()
	warmUp.Get("/", func(c fiber.Ctx) error { return c.SendStatus(fiber.StatusNoContent) })

	resp, err := warmUp.Test(httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil))
	if err != nil {
		fmt.Fprintf(os.Stderr, "warm-up request: %v\n", err)
		os.Exit(1)
	}
	_ = resp.Body.Close()

	os.Exit(m.Run())
}

// call sends one request to the example and returns the status code and the
// decoded JSON object of the response. bearer is sent as the Authorization
// header when it is not empty.
type call func(method, path, body, bearer string) (int, map[string]any)

// newTestApp builds the same app main serves, with keys in a directory that is
// removed when the test ends.
func newTestApp(t *testing.T) *fiber.App {
	t.Helper()

	cfg := authcore.DefaultConfig()
	cfg.EnableLogs = false
	cfg.KeysDir = t.TempDir()

	pwdMod, jwtMod, emailMod, err := newModules(cfg)
	if err != nil {
		t.Fatalf("newModules: %v", err)
	}
	app, err := newApp(pwdMod, jwtMod, emailMod)
	if err != nil {
		t.Fatalf("newApp: %v", err)
	}
	return app
}

// newExample returns a call function bound to a fresh app.
func newExample(t *testing.T) call {
	t.Helper()
	app := newTestApp(t)

	return func(method, path, body, bearer string) (int, map[string]any) {
		req := httptest.NewRequestWithContext(context.Background(), method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}

		// Timeout 0 disables app.Test's one-second default: Argon2id under the
		// race detector took longer than that on a loaded machine.
		resp, err := app.Test(req, fiber.TestConfig{Timeout: 0})
		if err != nil {
			t.Errorf("%s %s: %v", method, path, err)
			return 0, nil
		}
		defer resp.Body.Close()

		raw, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Errorf("%s %s: read body: %v", method, path, err)
		}
		var decoded map[string]any
		if err := json.Unmarshal(raw, &decoded); err != nil {
			t.Errorf("%s %s: body %q is not a JSON object: %v", method, path, raw, err)
		}
		return resp.StatusCode, decoded
	}
}

func credentials(email, password string) string {
	body, _ := json.Marshal(map[string]string{"email": email, "password": password})
	return string(body)
}

func refreshBody(token string) string {
	body, _ := json.Marshal(map[string]string{"refresh_token": token})
	return string(body)
}

// text returns body[key] as a string, or "" when it is absent.
func text(body map[string]any, key string) string {
	s, _ := body[key].(string)
	return s
}

// expect reports a failure naming the step when the status, or the "error"
// field of the body, is not the wanted one. wantError "" means no error field.
// It never prints the body: a response that should not have been served holds
// live tokens, and a test log is a log.
func expect(t *testing.T, step string, status int, body map[string]any, wantStatus int, wantError string) {
	t.Helper()
	if status != wantStatus {
		t.Errorf("%s: status %d, want %d", step, status, wantStatus)
	}
	if got := text(body, "error"); got != wantError {
		t.Errorf("%s: error %q, want %q", step, got, wantError)
	}
}

// nextSecond moves the clock of the synctest bubble past a second boundary.
// A refresh token carries iat and exp in whole seconds and keeps its jti, and
// on 2026-09-18 a rotation in the same second as the issuance returned the very
// same token. Without this step there is no "old" token to refuse. Inside the
// bubble the sleep returns at once: it advances fake time, it does not wait.
func nextSecond() {
	time.Sleep(time.Second)
}

// TestReadmeSequence walks the four steps of the README in order, then checks
// that the rotated-out refresh token is refused and its replacement accepted.
func TestReadmeSequence(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		do := newExample(t)

		status, body := do(http.MethodPost, "/register", credentials(readmeEmail, readmePassword), "")
		expect(t, "1. register", status, body, http.StatusCreated, "")

		status, body = do(http.MethodPost, "/login", credentials(readmeEmail, readmePassword), "")
		expect(t, "2. login", status, body, http.StatusOK, "")
		access, oldRefresh := text(body, "access_token"), text(body, "refresh_token")
		if access == "" || oldRefresh == "" {
			t.Fatal("2. login: no token pair in the response")
		}

		status, body = do(http.MethodGet, "/me", "", access)
		expect(t, "3. protected route", status, body, http.StatusOK, "")
		if got := text(body, "email"); got != readmeEmail {
			t.Errorf("3. protected route: email %q, want %q", got, readmeEmail)
		}
		if got := text(body, "user_id"); !uuidV7.MatchString(got) {
			t.Errorf("3. protected route: user_id %q is not a UUID v7", got)
		}

		status, body = do(http.MethodGet, "/me", "", "")
		expect(t, "3. protected route without a token", status, body, http.StatusUnauthorized, "missing token")

		nextSecond()

		status, body = do(http.MethodPost, "/refresh", refreshBody(oldRefresh), "")
		expect(t, "4. rotate", status, body, http.StatusOK, "")
		newAccess, newRefresh := text(body, "access_token"), text(body, "refresh_token")
		if newRefresh == "" || newRefresh == oldRefresh {
			t.Fatal("4. rotate: the refresh token was not replaced")
		}

		status, body = do(http.MethodGet, "/me", "", newAccess)
		expect(t, "rotated access token", status, body, http.StatusOK, "")

		status, body = do(http.MethodPost, "/refresh", refreshBody(oldRefresh), "")
		expect(t, "old refresh token", status, body, http.StatusUnauthorized, "invalid refresh token")

		status, body = do(http.MethodPost, "/refresh", refreshBody(newRefresh), "")
		expect(t, "current refresh token", status, body, http.StatusOK, "")
	})
}

// TestDuplicateRegistration checks that registering a taken address is refused
// and leaves the account as it was.
func TestDuplicateRegistration(t *testing.T) {
	const secondPassword = "An0ther-P@ssword!"
	do := newExample(t)

	status, body := do(http.MethodPost, "/register", credentials(readmeEmail, readmePassword), "")
	expect(t, "first registration", status, body, http.StatusCreated, "")

	status, body = do(http.MethodPost, "/register", credentials(readmeEmail, secondPassword), "")
	expect(t, "second registration of the address", status, body, http.StatusConflict, "email already registered")

	// Same request, free address: the refusal above was about the address.
	status, body = do(http.MethodPost, "/register", credentials("luz@example.com", secondPassword), "")
	expect(t, "registration of a free address", status, body, http.StatusCreated, "")

	status, body = do(http.MethodPost, "/login", credentials(readmeEmail, readmePassword), "")
	expect(t, "login with the original password", status, body, http.StatusOK, "")

	status, body = do(http.MethodPost, "/login", credentials(readmeEmail, secondPassword), "")
	expect(t, "login with the second password", status, body, http.StatusUnauthorized, "invalid credentials")
}

// TestConcurrentRedemption fires many redemptions of one refresh token at the
// handler at once and requires that exactly one of them is served.
func TestConcurrentRedemption(t *testing.T) {
	const redemptions = 32

	synctest.Test(t, func(t *testing.T) {
		do := newExample(t)

		status, body := do(http.MethodPost, "/register", credentials(readmeEmail, readmePassword), "")
		expect(t, "register", status, body, http.StatusCreated, "")
		status, body = do(http.MethodPost, "/login", credentials(readmeEmail, readmePassword), "")
		expect(t, "login", status, body, http.StatusOK, "")
		token := text(body, "refresh_token")
		if token == "" {
			t.Fatal("login: no refresh token in the response")
		}

		nextSecond()

		var (
			wg       sync.WaitGroup
			start    = make(chan struct{})
			statuses [redemptions]int
			bodies   [redemptions]map[string]any
		)
		for i := range redemptions {
			wg.Go(func() {
				<-start
				statuses[i], bodies[i] = do(http.MethodPost, "/refresh", refreshBody(token), "")
			})
		}
		close(start)
		wg.Wait()

		served, winner := 0, -1
		for i, status := range statuses {
			switch status {
			case http.StatusOK:
				served++
				winner = i
			case http.StatusUnauthorized:
				if got := text(bodies[i], "error"); got != "invalid refresh token" {
					t.Errorf("redemption %d: error %q, want %q", i, got, "invalid refresh token")
				}
			default:
				t.Errorf("redemption %d: status %d, want 200 or 401", i, status)
			}
		}
		if served != 1 {
			t.Fatalf("%d of %d redemptions of one refresh token were served, want exactly 1", served, redemptions)
		}

		status, body = do(http.MethodPost, "/refresh", refreshBody(text(bodies[winner], "refresh_token")), "")
		expect(t, "token handed to the one served redemption", status, body, http.StatusOK, "")
	})
}

func TestStoreInsertRefusesTakenEmail(t *testing.T) {
	db := newStore()

	if !db.insert(user{id: "first", email: "ana@example.com", passwordHash: "hash-1"}) {
		t.Fatal("insert of a free address reported false")
	}
	if db.insert(user{id: "second", email: "ana@example.com", passwordHash: "hash-2"}) {
		t.Error("insert of a taken address reported true")
	}
	if !db.insert(user{id: "third", email: "luz@example.com", passwordHash: "hash-2"}) {
		t.Error("insert of another free address reported false")
	}

	got, ok := db.findByEmail("ana@example.com")
	if !ok || got.id != "first" || got.passwordHash != "hash-1" {
		t.Errorf("account after the refused insert = %+v, want id first and hash-1", got)
	}
}

func TestStoreSwapRefreshHash(t *testing.T) {
	const email = "ana@example.com"

	tests := []struct {
		name       string
		email      string
		current    string
		wantSwap   bool
		wantStored string
	}{
		{name: "stored hash presented", email: email, current: "stored", wantSwap: true, wantStored: "next"},
		{name: "another hash presented", email: email, current: "other", wantSwap: false, wantStored: "stored"},
		{name: "empty hash presented", email: email, current: "", wantSwap: false, wantStored: "stored"},
		{name: "unknown account", email: "luz@example.com", current: "stored", wantSwap: false, wantStored: "stored"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := newStore()
			db.insert(user{id: "id", email: email})
			db.setRefreshHash(email, "stored")

			if got := db.swapRefreshHash(tt.email, tt.current, "next"); got != tt.wantSwap {
				t.Errorf("swapRefreshHash = %v, want %v", got, tt.wantSwap)
			}
			if got, _ := db.findByEmail(email); got.refreshHash != tt.wantStored {
				t.Errorf("stored hash = %q, want %q", got.refreshHash, tt.wantStored)
			}
		})
	}
}

// A hash can be swapped out once. The second redemption presents a hash that
// is no longer the stored one and must change nothing.
func TestStoreSwapRefreshHashConsumesOnce(t *testing.T) {
	const email = "ana@example.com"
	db := newStore()
	db.insert(user{id: "id", email: email})
	db.setRefreshHash(email, "stored")

	if !db.swapRefreshHash(email, "stored", "first-winner") {
		t.Fatal("first swap of the stored hash reported false")
	}
	if db.swapRefreshHash(email, "stored", "second-winner") {
		t.Error("second swap of the same hash reported true")
	}
	if got, _ := db.findByEmail(email); got.refreshHash != "first-winner" {
		t.Errorf("stored hash = %q, want %q", got.refreshHash, "first-winner")
	}
}

func TestStoreFindByRefreshHash(t *testing.T) {
	db := newStore()
	db.insert(user{id: "never-logged-in", email: "luz@example.com"})
	db.insert(user{id: "logged-in", email: "ana@example.com"})
	db.setRefreshHash("ana@example.com", "stored")

	if got, ok := db.findByRefreshHash("stored"); !ok || got.id != "logged-in" {
		t.Errorf("findByRefreshHash(stored) = %+v, %v, want the logged-in account", got, ok)
	}
	if got, ok := db.findByRefreshHash(""); ok {
		t.Errorf("findByRefreshHash of the empty hash matched %+v, want no account", got)
	}
	if got, ok := db.findByRefreshHash("other"); ok {
		t.Errorf("findByRefreshHash(other) matched %+v, want no account", got)
	}
}

func TestStoreSetRefreshHashUnknownAccount(t *testing.T) {
	db := newStore()
	if db.setRefreshHash("ana@example.com", "hash") {
		t.Error("setRefreshHash for an unknown account reported true")
	}
}

func TestNewUserIDIsUUIDv7(t *testing.T) {
	seen := map[string]bool{}
	for range 1000 {
		id := newUserID()
		if !uuidV7.MatchString(id) {
			t.Fatalf("newUserID() = %q, not a canonical UUID v7", id)
		}
		if seen[id] {
			t.Fatalf("newUserID() returned %q twice", id)
		}
		seen[id] = true
	}
}
