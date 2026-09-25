package credential

// Shared test infrastructure for the credential package. The package-internal
// test scope (package credential rather than credential_test) lets the suite
// replace the module's clock with clock.Fixed so TTL and expiry assertions
// run deterministically without real sleeps. Same pattern as auth/totp.

import (
	"crypto/ed25519"
	"crypto/rand"
	"sync"
	"testing"
	"time"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/internal/clock"
)

// ---- test doubles -----------------------------------------------------------

type fakeKeys struct{ secret []byte }

func (fakeKeys) PrivateKey() ed25519.PrivateKey { return nil }
func (fakeKeys) PublicKey() ed25519.PublicKey   { return nil }
func (k fakeKeys) RefreshSecret() []byte        { return k.secret }
func (fakeKeys) KeyID() string                  { return "test" }

type fakeProvider struct{ keys authcore.Keys }

func (fakeProvider) Config() authcore.Config { return authcore.DefaultConfig() }
func (fakeProvider) Logger() authcore.Logger { return silentLogger{} }
func (p fakeProvider) Keys() authcore.Keys   { return p.keys }

type silentLogger struct{}

func (silentLogger) Debug(string, ...any) {}
func (silentLogger) Info(string, ...any)  {}
func (silentLogger) Warn(string, ...any)  {}
func (silentLogger) Error(string, ...any) {}

func newFakeProvider(tb testing.TB) fakeProvider {
	tb.Helper()
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		tb.Fatalf("generate test HMAC secret: %v", err)
	}
	return fakeProvider{keys: fakeKeys{secret: secret}}
}

// epoch is a fixed reference time used across tests that need a known
// "now" without sleeping. Picked well inside the year-292277396-safe
// range so future-skew tests stay clean.
var epoch = time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)

// newCred builds a Credential with a fixed clock pinned to epoch. Tests
// that need a different clock override c.clock directly.
func newCred(tb testing.TB, cfg ...Config) *Credential {
	tb.Helper()
	mod, err := New(newFakeProvider(tb), cfg...)
	if err != nil {
		tb.Fatalf("credential.New: %v", err)
	}
	mod.clock = clock.Fixed(epoch)
	return mod
}

// ---- Name / default config --------------------------------------------------

func TestName(t *testing.T) {
	if got := newCred(t).Name(); got != "credential" {
		t.Errorf("Name() = %q, want credential", got)
	}
}

func TestNew_DefaultConfigSucceeds(t *testing.T) {
	if _, err := New(newFakeProvider(t)); err != nil {
		t.Errorf("New() with default config returned error: %v", err)
	}
}

// TestNew_SatisfiesModule is the compile-time-equivalent runtime assertion.
// The var _ authcore.Module = (*Credential)(nil) line at the top of
// credential.go already proves it at build time; this test exists so the
// behaviour is named.
func TestNew_SatisfiesModule(t *testing.T) {
	var m authcore.Module = newCred(t)
	if m.Name() != "credential" {
		t.Errorf("module Name() = %q, want credential", m.Name())
	}
}

// ---- Issue / Verify happy path ---------------------------------------------

// TestIssue_ReturnsIssuedWithTokenAndHash pins the result shape: Token is
// non-empty, Hash is non-empty, and Hash is a 64-char lowercase hex string
// (HMAC-SHA256 output).
func TestIssue_ReturnsIssuedWithTokenAndHash(t *testing.T) {
	c := newCred(t)
	issued, err := c.Issue("reset", "alice@example.com")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if issued.Token == "" {
		t.Error("issued.Token is empty")
	}
	if issued.Hash == "" {
		t.Error("issued.Hash is empty")
	}
	if len(issued.Hash) != 64 {
		t.Errorf("issued.Hash length = %d, want 64 (hex SHA-256)", len(issued.Hash))
	}
}

// TestIssue_FiftyConcurrentCallsProduceDistinctTokens is the
// concurrency-safety check the Issue path must pass. An earlier draft
// stored the most recent token and hash on the receiver under a mutex,
// which both kept the raw token (the value the caller must show exactly
// once) alive in memory for the module's lifetime and made a single
// shared-mutex around a per-call counter the obvious target of a
// contention regression. The test pins the externally observable
// property: fifty concurrent Issue calls must produce fifty distinct
// tokens with no race detected under -race.
//
// Note: the test does NOT directly inspect the receiver for "per-issue
// state": Go has no portable way to do that without extending the
// module's surface. The intended property is enforced by the absence of
// any per-call write to the module under -race.
func TestIssue_FiftyConcurrentCallsProduceDistinctTokens(t *testing.T) {
	c := newCred(t)

	const n = 50
	tokens := make([]string, n)
	var wg sync.WaitGroup
	for i := range tokens {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			issued, err := c.Issue("reset", "alice@example.com")
			if err != nil {
				t.Errorf("Issue: %v", err)
				return
			}
			tokens[i] = issued.Token
		}(i)
	}
	wg.Wait()

	seen := make(map[string]struct{}, n)
	for i, tok := range tokens {
		if tok == "" {
			t.Fatalf("token %d is empty", i)
		}
		if _, dup := seen[tok]; dup {
			t.Fatalf("token %d repeated: Issue is not drawing fresh randomness", i)
		}
		seen[tok] = struct{}{}
	}
}

// TestVerify_RoundTrip is the happy path: Issue, then Verify with the
// same purpose, subject, token, hash, and issuedAt==now, must succeed.
func TestVerify_RoundTrip(t *testing.T) {
	c := newCred(t)
	issued, err := c.Issue("reset", "alice@example.com")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := c.Verify("reset", "alice@example.com", issued.Token, issued.Hash, epoch); err != nil {
		t.Errorf("Verify round trip failed: %v", err)
	}
}
