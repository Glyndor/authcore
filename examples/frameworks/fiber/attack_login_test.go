package main

import (
	"bytes"
	"log"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
)

// medianLogin returns the median wall time of n login requests.
func medianLogin(t *testing.T, h *fiber.App, body string, n int) time.Duration {
	t.Helper()
	times := make([]time.Duration, n)
	for i := range times {
		start := time.Now()
		send(t, h, http.MethodPost, "/login", body, nil)
		times[i] = time.Since(start)
	}
	slices.Sort(times)
	return times[n/2]
}

// TestLoginDoesNotRevealWhetherAnAccountExists compares what an attacker can
// observe for a registered address with a wrong password and for an address
// nobody registered: the response and the time it takes.
func TestLoginDoesNotRevealWhetherAnAccountExists(t *testing.T) {
	h := newTestApp(t)
	send(t, h, http.MethodPost, "/register", credentials(readmeEmail, readmePassword), nil)

	wrong := send(t, h, http.MethodPost, "/login", credentials(readmeEmail, "Wr0ng-P@ssword!!"), nil)
	unknown := send(t, h, http.MethodPost, "/login", credentials("nobody@example.com", "Wr0ng-P@ssword!!"), nil)
	malformed := send(t, h, http.MethodPost, "/login", credentials("not an address", "Wr0ng-P@ssword!!"), nil)
	if wrong.code != http.StatusUnauthorized || wrong.body != unknown.body || wrong.body != malformed.body {
		t.Errorf("responses differ: %d %q / %d %q / %d %q",
			wrong.code, wrong.body, unknown.code, unknown.body, malformed.code, malformed.body)
	}

	const rounds = 5
	known := medianLogin(t, h, credentials(readmeEmail, "Wr0ng-P@ssword!!"), rounds)
	absent := medianLogin(t, h, credentials("nobody@example.com", "Wr0ng-P@ssword!!"), rounds)
	if absent < known/2 {
		t.Errorf("unknown account answers in %v, a wrong password in %v: the gap shows which addresses exist", absent, known)
	}
}

// TestLoginRefusesHugePasswordsBeforeHashing checks that a password far beyond
// any policy is not fed to Argon2id: the refusal must cost far less than a
// derivation.
func TestLoginRefusesHugePasswordsBeforeHashing(t *testing.T) {
	h := newTestApp(t)
	send(t, h, http.MethodPost, "/register", credentials(readmeEmail, readmePassword), nil)

	const rounds = 5
	normal := medianLogin(t, h, credentials(readmeEmail, "Wr0ng-P@ssword!!"), rounds)
	huge := medianLogin(t, h, credentials(readmeEmail, strings.Repeat("A", 4000)), rounds)
	if huge > normal/2 {
		t.Errorf("a 4000-byte password takes %v, a normal wrong one %v: it was hashed", huge, normal)
	}
	if r := send(t, h, http.MethodPost, "/login", credentials(readmeEmail, strings.Repeat("A", 4000)), nil); r.code != http.StatusUnauthorized {
		t.Errorf("status %d, want 401", r.code)
	}
}

// TestEmailIsCanonical checks that the address is normalized before it becomes
// a key, and validated before it is stored.
func TestEmailIsCanonical(t *testing.T) {
	h := newTestApp(t)

	if r := send(t, h, http.MethodPost, "/register", credentials("Ana@Example.COM", readmePassword), nil); r.code != http.StatusCreated {
		t.Fatalf("register: status %d", r.code)
	}
	if r := send(t, h, http.MethodPost, "/register", credentials("ana@example.com", "An0ther-P@ssword!"), nil); r.code != http.StatusConflict {
		t.Errorf("same address in another case: status %d, want 409", r.code)
	}
	if r := send(t, h, http.MethodPost, "/login", credentials("  ANA@example.com ", readmePassword), nil); r.code != http.StatusOK {
		t.Errorf("login with another spelling of the address: status %d, want 200", r.code)
	}

	for _, bad := range []string{"", "plain", "a@b", "x@example..com", "a\nb@example.com", "a@example.com\r\nBcc: z@example.com"} {
		r := send(t, h, http.MethodPost, "/register", credentials(bad, readmePassword), nil)
		if r.code != http.StatusBadRequest {
			t.Errorf("register %q: status %d, want 400", bad, r.code)
		}
	}
}

// TestRegisterRefusesWeakAndHugePasswords checks the password policy runs
// before any hashing, including on a body just under the size cap.
func TestRegisterRefusesWeakAndHugePasswords(t *testing.T) {
	h := newTestApp(t)
	for _, pw := range []string{"short", "alllowercase-password", strings.Repeat("Aa1!", 3000), "Str0ng-P@ss\x00word!"} {
		r := send(t, h, http.MethodPost, "/register", credentials("luz@example.com", pw), nil)
		if r.code != http.StatusBadRequest && r.code != http.StatusRequestEntityTooLarge {
			t.Errorf("password of %d bytes: status %d, want 400", len(pw), r.code)
		}
	}
}

// TestLogsHoldNoSecrets runs the whole flow, failures included, with the
// standard logger captured. No password and no token may appear in it.
func TestLogsHoldNoSecrets(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	h := newTestApp(t)
	access, refresh := session(t, h)
	send(t, h, http.MethodPost, "/login", credentials(readmeEmail, "Wr0ng-P@ssword!!"), nil)
	send(t, h, http.MethodPost, "/login", credentials("a\nFORGED log line", "Wr0ng-P@ssword!!"), nil)
	send(t, h, http.MethodGet, "/me", "", authHeader("Bearer "+access+"x"))
	send(t, h, http.MethodGet, "/me", "", authHeader("Bearer "+refresh))
	send(t, h, http.MethodPost, "/refresh", refreshBody(access), nil)

	logged := buf.String()
	for name, secret := range map[string]string{
		"password": readmePassword, "wrong password": "Wr0ng-P@ssword!!",
		"access token": access, "refresh token": refresh,
	} {
		if strings.Contains(logged, secret) {
			t.Errorf("the %s is in the log", name)
		}
	}
	if strings.Contains(logged, "\nFORGED log line") {
		t.Error("a hostile address forged a log line")
	}
}

// TestRotationLeavesAccessTokenValid pins the behaviour the README documents:
// there is no revocation list, so an access token lives until it expires even
// after its session was rotated away.
func TestRotationLeavesAccessTokenValid(t *testing.T) {
	h := newTestApp(t)
	access, refresh := session(t, h)
	time.Sleep(1100 * time.Millisecond)

	if r := send(t, h, http.MethodPost, "/refresh", refreshBody(refresh), nil); r.code != http.StatusOK {
		t.Fatalf("refresh: status %d", r.code)
	}
	if r := send(t, h, http.MethodGet, "/me", "", authHeader("Bearer "+access)); r.code != http.StatusOK {
		t.Errorf("status %d: the README says the old access token stays valid until it expires", r.code)
	}
}

// TestReadmeDocumentsTheLimits keeps the README honest about what the example
// leaves out, so nobody copies the gaps into production unaware of them.
func TestReadmeDocumentsTheLimits(t *testing.T) {
	raw, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	readme := strings.ToLower(string(raw))
	for _, want := range []string{"rate limit", "logout", "until it expires", "enumerat", "in-memory"} {
		if !strings.Contains(readme, want) {
			t.Errorf("README does not mention %q", want)
		}
	}
}
