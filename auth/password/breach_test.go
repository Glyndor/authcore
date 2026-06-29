package password

import (
	"context"
	"crypto/sha1" //nolint:gosec // mirrors the production k-anonymity hashing under test.
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/text/unicode/norm"
)

// digestParts returns the uppercase SHA-1 prefix (5) and suffix (35) of pw,
// matching what HIBPChecker sends and compares.
func digestParts(pw string) (prefix, suffix string) {
	sum := sha1.Sum([]byte(pw)) //nolint:gosec // test mirror of the k-anonymity hash.
	d := strings.ToUpper(hex.EncodeToString(sum[:]))
	return d[:5], d[5:]
}

// ---- ListChecker ------------------------------------------------------------

func TestListChecker_hitAndMiss(t *testing.T) {
	c := NewListChecker([]string{"password123", "hunter2"})
	for _, tc := range []struct {
		pw   string
		want bool
	}{
		{"password123", true},
		{"hunter2", true},
		{"not-in-the-list", false},
	} {
		got, err := c.IsBreached(context.Background(), tc.pw)
		if err != nil {
			t.Fatalf("IsBreached(%q) error = %v", tc.pw, err)
		}
		if got != tc.want {
			t.Errorf("IsBreached(%q) = %v, want %v", tc.pw, got, tc.want)
		}
	}
}

func TestListChecker_normalisesNFC(t *testing.T) {
	// Store the decomposed form, query the precomposed form: they must match
	// because both sides are normalised to NFC.
	base := "café-Passw0rd!"
	nfdForm := norm.NFD.String(base)
	nfcForm := norm.NFC.String(base)
	if nfdForm == nfcForm {
		t.Skip("base string has no precomposed/decomposed distinction")
	}
	c := NewListChecker([]string{nfdForm})
	got, err := c.IsBreached(context.Background(), nfcForm)
	if err != nil {
		t.Fatalf("IsBreached error = %v", err)
	}
	if !got {
		t.Error("expected NFC-normalised lookup to match the NFD-stored entry")
	}
}

// ---- HIBPChecker ------------------------------------------------------------

func TestHIBPChecker_breached(t *testing.T) {
	const pw = "Sup3rSecret!Pass"
	prefix, suffix := digestParts(pw)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// k-anonymity: only the prefix may be requested, never the full digest.
		if r.URL.Path != "/range/"+prefix {
			t.Errorf("requested path = %q, want /range/%s", r.URL.Path, prefix)
		}
		if r.Header.Get("Add-Padding") != "true" {
			t.Errorf("Add-Padding header = %q, want true", r.Header.Get("Add-Padding"))
		}
		// Real match (count > 0) plus an unrelated suffix and a padding line.
		fmt.Fprint(w, "0000000000000000000000000000000000A:3\r\n")
		fmt.Fprintf(w, "%s:42\r\n", suffix)
		fmt.Fprint(w, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:0\r\n")
	}))
	defer srv.Close()

	c := NewHIBPChecker(WithBaseURL(srv.URL))
	got, err := c.IsBreached(context.Background(), pw)
	if err != nil {
		t.Fatalf("IsBreached error = %v", err)
	}
	if !got {
		t.Error("expected password to be reported as breached")
	}
}

func TestHIBPChecker_notBreached(t *testing.T) {
	const pw = "An0ther!Unique@Pw"
	_, suffix := digestParts(pw)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Same suffix but count 0 (padding) plus an unrelated entry — no real hit.
		fmt.Fprintf(w, "%s:0\r\n", suffix)
		fmt.Fprint(w, "1111111111111111111111111111111111B:9\r\n")
	}))
	defer srv.Close()

	c := NewHIBPChecker(WithBaseURL(srv.URL))
	got, err := c.IsBreached(context.Background(), pw)
	if err != nil {
		t.Fatalf("IsBreached error = %v", err)
	}
	if got {
		t.Error("expected password not to be reported as breached (padding count 0)")
	}
}

func TestHIBPChecker_nonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	c := NewHIBPChecker(WithBaseURL(srv.URL))
	if _, err := c.IsBreached(context.Background(), "whatever-Passw0rd!"); err == nil {
		t.Error("expected an error on non-200 status")
	}
}

func TestHIBPChecker_transportError(t *testing.T) {
	// Point at a closed server to force a transport error.
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close()

	c := NewHIBPChecker(WithBaseURL(url))
	if _, err := c.IsBreached(context.Background(), "whatever-Passw0rd!"); err == nil {
		t.Error("expected a transport error against a closed server")
	}
}

// ---- CheckBreached ----------------------------------------------------------

// stubChecker is a programmable BreachChecker for CheckBreached tests.
type stubChecker struct {
	breached bool
	err      error
	gotPw    string
}

func (s *stubChecker) IsBreached(_ context.Context, plaintext string) (bool, error) {
	s.gotPw = plaintext
	return s.breached, s.err
}

func modWithChecker(t *testing.T, c BreachChecker) *Password {
	t.Helper()
	cfg := DefaultConfig()
	cfg.BreachChecker = c
	mod, err := New(fakeProvider{}, cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return mod
}

func TestCheckBreached_noCheckerConfigured(t *testing.T) {
	p := newMod(t)
	err := p.CheckBreached(context.Background(), "anything-Passw0rd!")
	if !errors.Is(err, ErrNoBreachChecker) {
		t.Errorf("expected ErrNoBreachChecker, got %v", err)
	}
}

func TestCheckBreached_breached(t *testing.T) {
	p := modWithChecker(t, &stubChecker{breached: true})
	err := p.CheckBreached(context.Background(), "leaked-Passw0rd!")
	if !errors.Is(err, ErrBreachedPassword) {
		t.Errorf("expected ErrBreachedPassword, got %v", err)
	}
}

func TestCheckBreached_clean(t *testing.T) {
	p := modWithChecker(t, &stubChecker{breached: false})
	if err := p.CheckBreached(context.Background(), "fresh-Passw0rd!"); err != nil {
		t.Errorf("expected nil for a clean password, got %v", err)
	}
}

func TestCheckBreached_checkerErrorIsWrapped(t *testing.T) {
	sentinel := errors.New("dns boom")
	p := modWithChecker(t, &stubChecker{err: sentinel})
	err := p.CheckBreached(context.Background(), "any-Passw0rd!")
	if !errors.Is(err, sentinel) {
		t.Errorf("expected wrapped checker error, got %v", err)
	}
	if errors.Is(err, ErrBreachedPassword) {
		t.Error("a lookup error must not be reported as a breach")
	}
}

func TestCheckBreached_normalisesNFC(t *testing.T) {
	stub := &stubChecker{}
	p := modWithChecker(t, stub)
	base := "café-Passw0rd!"
	if err := p.CheckBreached(context.Background(), norm.NFD.String(base)); err != nil {
		t.Fatalf("CheckBreached error = %v", err)
	}
	if stub.gotPw != norm.NFC.String(base) {
		t.Errorf("checker received %q, want NFC-normalised form", stub.gotPw)
	}
}
