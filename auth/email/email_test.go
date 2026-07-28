package email

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Glyndor/authcore"
)

// ---- test helpers -----------------------------------------------------------

type fakeProvider struct{}

func (fakeProvider) Config() authcore.Config { return authcore.DefaultConfig() }
func (fakeProvider) Logger() authcore.Logger { return silentLogger{} }
func (fakeProvider) Keys() authcore.Keys     { return nil }

type silentLogger struct{}

func (silentLogger) Debug(string, ...any) {}
func (silentLogger) Info(string, ...any)  {}
func (silentLogger) Warn(string, ...any)  {}
func (silentLogger) Error(string, ...any) {}

func newMod(t *testing.T) *Email {
	t.Helper()
	m, err := New(fakeProvider{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return m
}

// ---- New() ------------------------------------------------------------------

func TestNew_succeeds(t *testing.T) {
	if _, err := New(fakeProvider{}); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}

func TestName(t *testing.T) {
	if got := newMod(t).Name(); got != "email" {
		t.Errorf("Name() = %q, want %q", got, "email")
	}
}

// ---- normalize() — internal -------------------------------------------------

func TestNormalize_lowercases(t *testing.T) {
	if got := normalize("USER@EXAMPLE.COM"); got != "user@example.com" {
		t.Errorf("got %q", got)
	}
}

func TestNormalize_trimsSpaces(t *testing.T) {
	if got := normalize("  user@example.com  "); got != "user@example.com" {
		t.Errorf("got %q", got)
	}
}

func TestNormalize_mixedCaseAndSpaces(t *testing.T) {
	if got := normalize("  Ana@Example.COM  "); got != "ana@example.com" {
		t.Errorf("got %q", got)
	}
}

// ---- validate() — valid addresses (internal) --------------------------------

func TestValidate_simpleValid(t *testing.T) {
	valid := []string{
		"user@example.com",
		"user.name@example.com",
		"user+tag@example.co.uk",
		"a@b.io",
		"user@sub.domain.example.com",
	}
	for _, addr := range valid {
		if err := validate(addr); err != nil {
			t.Errorf("validate(%q) = %v, want nil", addr, err)
		}
	}
}

// ---- validate() — invalid addresses (internal) ------------------------------

func TestValidate_empty(t *testing.T) {
	if err := validate(""); !errors.Is(err, ErrInvalidEmail) {
		t.Errorf("expected ErrInvalidEmail, got %v", err)
	}
}

func TestValidate_tooLong(t *testing.T) {
	local := "a"
	for len(local+"@b.com") <= 254 {
		local += "a"
	}
	if err := validate(local + "@b.com"); !errors.Is(err, ErrInvalidEmail) {
		t.Errorf("expected ErrInvalidEmail for too-long address")
	}
}

func TestValidate_noAt(t *testing.T) {
	if err := validate("userexample.com"); !errors.Is(err, ErrInvalidEmail) {
		t.Errorf("expected ErrInvalidEmail, got %v", err)
	}
}

func TestValidate_localPartTooLong(t *testing.T) {
	local := ""
	for i := 0; i < 65; i++ {
		local += "a"
	}
	if err := validate(local + "@example.com"); !errors.Is(err, ErrInvalidEmail) {
		t.Errorf("expected ErrInvalidEmail for local part > 64 chars")
	}
}

func TestValidate_domainNoDot(t *testing.T) {
	if err := validate("user@localhost"); !errors.Is(err, ErrInvalidEmail) {
		t.Errorf("expected ErrInvalidEmail, got %v", err)
	}
}

func TestValidate_domainLeadingDot(t *testing.T) {
	if err := validate("user@.example.com"); !errors.Is(err, ErrInvalidEmail) {
		t.Errorf("expected ErrInvalidEmail, got %v", err)
	}
}

func TestValidate_domainTrailingDot(t *testing.T) {
	if err := validate("user@example.com."); !errors.Is(err, ErrInvalidEmail) {
		t.Errorf("expected ErrInvalidEmail, got %v", err)
	}
}

func TestValidate_domainConsecutiveDots(t *testing.T) {
	if err := validate("user@example..com"); !errors.Is(err, ErrInvalidEmail) {
		t.Errorf("expected ErrInvalidEmail, got %v", err)
	}
}

func TestValidate_withDisplayName(t *testing.T) {
	if err := validate("Ana <ana@example.com>"); !errors.Is(err, ErrInvalidEmail) {
		t.Errorf("expected ErrInvalidEmail for display name format")
	}
}

func TestValidate_addressLiteralRejected(t *testing.T) {
	for _, addr := range []string{
		"user@[192.168.1.1]",
		"user@[IPv6:2001:db8::1]",
	} {
		if err := validate(addr); !errors.Is(err, ErrInvalidEmail) {
			t.Errorf("expected ErrInvalidEmail for address literal %q, got %v", addr, err)
		}
	}
}

// ---- ErrInvalidEmail wraps a reason -----------------------------------------

func TestValidate_wrapsReason(t *testing.T) {
	err := validate("")
	if !errors.Is(err, ErrInvalidEmail) {
		t.Fatalf("expected ErrInvalidEmail, got %v", err)
	}
	reason := errors.Unwrap(err)
	if reason == nil {
		t.Fatal("expected wrapped reason, got nil")
	}
	if reason.Error() == "" {
		t.Error("wrapped reason must not be empty")
	}
}

// ---- ValidateAndNormalize() -------------------------------------------------

func TestValidateAndNormalize_normalizes(t *testing.T) {
	m := newMod(t)
	got, err := m.ValidateAndNormalize("  USER@EXAMPLE.COM  ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "user@example.com" {
		t.Errorf("got %q, want %q", got, "user@example.com")
	}
}

func TestValidateAndNormalize_idnSubdomainEachLabelConverted(t *testing.T) {
	// When a multi-label IDN domain is supplied, every Unicode label must
	// be converted to its punycode form, not just the rightmost one.
	got, err := newMod(t).ValidateAndNormalize("user@süd.münchen.de")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "user@xn--sd-xka.xn--mnchen-3ya.de"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestValidateAndNormalize_idnWithOverlongLabelRejected(t *testing.T) {
	// idna.Lookup caps a single label at 63 characters. When ToASCII cannot
	// produce a valid ASCII form, normalize falls back to the raw input and
	// the downstream validator rejects it with ErrInvalidEmail.
	overlongLabel := strings.Repeat("ä", 60) // ~120 bytes UTF-8, punycode expands further → >63
	_, err := newMod(t).ValidateAndNormalize("user@" + overlongLabel + ".com")
	if !errors.Is(err, ErrInvalidEmail) {
		t.Errorf("expected ErrInvalidEmail for overlong IDN label, got %v", err)
	}
}

func TestValidateAndNormalize_idnDomainConvertedToPunycode(t *testing.T) {
	// "münchen.de" is a legitimate German internationalised domain name.
	// Without IDN support the validator rejects it as non-ASCII; with IDN
	// support it is converted to its punycode (xn--mnchen-3ya.de) form that
	// DNS can actually resolve.
	got, err := newMod(t).ValidateAndNormalize("user@münchen.de")
	if err != nil {
		t.Fatalf("unexpected error for IDN email: %v", err)
	}
	want := "user@xn--mnchen-3ya.de"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestValidateAndNormalize_invalidReturnsError(t *testing.T) {
	_, err := newMod(t).ValidateAndNormalize("not-an-email")
	if !errors.Is(err, ErrInvalidEmail) {
		t.Errorf("expected ErrInvalidEmail, got %v", err)
	}
}

func TestValidateAndNormalize_emptyReturnsError(t *testing.T) {
	_, err := newMod(t).ValidateAndNormalize("")
	if !errors.Is(err, ErrInvalidEmail) {
		t.Errorf("expected ErrInvalidEmail, got %v", err)
	}
}

// ---- VerifyDomain() tests ---------------------------------------------------

// primeCache directly writes a cache entry, bypassing DNS, so we can test
// cache hit behaviour without network access.
func primeCache(m *Email, domain string, hasMX bool, ttl time.Duration) {
	m.mu.Lock()
	m.cache[domain] = cacheEntry{hasMX: hasMX, expiresAt: time.Now().Add(ttl)}
	m.mu.Unlock()
}

func TestVerifyDomain_cachedPositiveReturnsNil(t *testing.T) {
	m := newMod(t)
	primeCache(m, "example.com", true, time.Minute)

	if err := m.VerifyDomain(context.Background(), "user@example.com"); err != nil {
		t.Errorf("expected nil, got %v", err)
	}
}

func TestVerifyDomain_cachedNegativeReturnsErrDomainNoMX(t *testing.T) {
	m := newMod(t)
	primeCache(m, "nodomain.example", false, time.Minute)

	err := m.VerifyDomain(context.Background(), "user@nodomain.example")
	if !errors.Is(err, ErrDomainNoMX) {
		t.Errorf("expected ErrDomainNoMX, got %v", err)
	}
}

func TestVerifyDomain_expiredCacheHitsDNS(t *testing.T) {
	m := newMod(t)
	// Write an expired positive entry — it must NOT be used.
	m.mu.Lock()
	m.cache["example.com"] = cacheEntry{hasMX: true, expiresAt: time.Now().Add(-time.Second)}
	m.mu.Unlock()

	// DNS will fail (no real network in unit tests using a broken resolver).
	m.resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, errors.New("no network")
		},
	}
	err := m.VerifyDomain(context.Background(), "user@example.com")
	if !errors.Is(err, ErrDomainUnresolvable) {
		t.Errorf("expected ErrDomainUnresolvable after cache miss + DNS failure, got %v", err)
	}
}

func TestVerifyDomain_dnsFailureReturnsErrDomainUnresolvable(t *testing.T) {
	m := newMod(t)
	m.resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, errors.New("no network")
		},
	}
	err := m.VerifyDomain(context.Background(), "user@unreachable.example")
	if !errors.Is(err, ErrDomainUnresolvable) {
		t.Errorf("expected ErrDomainUnresolvable, got %v", err)
	}
}

func TestVerifyDomain_dnsFailureIsWrapped(t *testing.T) {
	m := newMod(t)
	m.resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, errors.New("no network")
		},
	}
	err := m.VerifyDomain(context.Background(), "user@unreachable.example")
	if errors.Unwrap(err) == nil {
		t.Error("ErrDomainUnresolvable must wrap the underlying DNS error")
	}
}

func TestVerifyDomain_noAtSignReturnsErrDomainNoMX(t *testing.T) {
	m := newMod(t)
	err := m.VerifyDomain(context.Background(), "notanemail")
	if !errors.Is(err, ErrDomainNoMX) {
		t.Errorf("expected ErrDomainNoMX for address with no '@', got %v", err)
	}
}

func TestVerifyDomain_cachedDnsFailureReturnsErrDomainUnresolvable(t *testing.T) {
	// Regression: a DNS failure cached as hasMX=false must NOT return
	// ErrDomainNoMX on subsequent cache hits — that would incorrectly block
	// the user. It must return ErrDomainUnresolvable (soft failure).
	m := newMod(t)
	m.mu.Lock()
	m.cache["unreachable.example"] = cacheEntry{
		dnsFailure: true,
		expiresAt:  time.Now().Add(time.Minute),
	}
	m.mu.Unlock()

	err := m.VerifyDomain(context.Background(), "user@unreachable.example")
	if !errors.Is(err, ErrDomainUnresolvable) {
		t.Errorf("cached DNS failure must return ErrDomainUnresolvable, got %v", err)
	}
	if errors.Is(err, ErrDomainNoMX) {
		t.Error("cached DNS failure must NOT return ErrDomainNoMX")
	}
}

func TestVerifyDomain_cacheDropsEntryWhenFull(t *testing.T) {
	m := newMod(t)

	// Fill the cache to maxCacheSize with live entries.
	m.mu.Lock()
	for i := range maxCacheSize {
		m.cache[fmt.Sprintf("live%d.example", i)] = cacheEntry{
			hasMX:     true,
			expiresAt: time.Now().Add(time.Hour),
		}
	}
	m.mu.Unlock()

	// Storing a new entry must be silently dropped when cache is full.
	m.store("new.example", cacheEntry{hasMX: true, expiresAt: time.Now().Add(time.Minute)})

	m.mu.RLock()
	_, ok := m.cache["new.example"]
	m.mu.RUnlock()

	if ok {
		t.Error("store must drop new entries silently when cache is at maxCacheSize")
	}
}

func TestEvictExpired_removesStaleKeepsLive(t *testing.T) {
	m := newMod(t)
	m.mu.Lock()
	m.cache["stale.example"] = cacheEntry{hasMX: true, expiresAt: time.Now().Add(-time.Second)}
	m.cache["live.example"] = cacheEntry{hasMX: true, expiresAt: time.Now().Add(time.Minute)}
	m.mu.Unlock()

	m.evictExpired()

	m.mu.RLock()
	_, staleOk := m.cache["stale.example"]
	_, liveOk := m.cache["live.example"]
	m.mu.RUnlock()

	if staleOk {
		t.Error("evictExpired must remove stale entries")
	}
	if !liveOk {
		t.Error("evictExpired must keep live entries")
	}
}

func TestClose_isIdempotent(t *testing.T) {
	m := newMod(t)
	m.Close()
	m.Close() // must not panic
}

func TestVerifyDomain_dnsFailureCachesNegativeBriefly(t *testing.T) {
	m := newMod(t)
	m.resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, errors.New("no network")
		},
	}
	_ = m.VerifyDomain(context.Background(), "user@unreachable.example")

	// Second call must hit the cache (no second DNS attempt).
	// We verify by reading the cache directly.
	m.mu.RLock()
	entry, ok := m.cache["unreachable.example"]
	m.mu.RUnlock()
	if !ok {
		t.Fatal("expected a cache entry after DNS failure")
	}
	if entry.hasMX {
		t.Error("failed DNS lookup must cache hasMX=false")
	}
	if time.Until(entry.expiresAt) > 31*time.Second {
		t.Errorf("negative DNS failure TTL should be ≤30 s, got %v", time.Until(entry.expiresAt))
	}
}

// TestValidate_tooLong above builds a ~249-character local part, so it is
// refused by the 64-character local-part rule and never reaches the total
// length check — deleting the 254 guard leaves it green. A total over 254 has
// to be assembled from parts that are each individually legal.
func TestValidate_tooLongWithEveryPartIndividuallyLegal(t *testing.T) {
	local := strings.Repeat("a", 60) // under the 64 limit
	label := strings.Repeat("b", 60) // under the 63-byte DNS label limit
	domain := label + "." + label + "." + label + "." + label + ".com"
	address := local + "@" + domain

	if len(address) <= 254 {
		t.Fatalf("fixture is only %d characters, it has to exceed 254 to test anything", len(address))
	}
	if len(local) > 64 {
		t.Fatal("fixture's local part breaks its own premise")
	}

	err := validate(address)
	if !errors.Is(err, ErrInvalidEmail) {
		t.Fatalf("an address over 254 characters must be refused, got: %v", err)
	}
	if !strings.Contains(err.Error(), "254") {
		t.Fatalf("refused for the wrong reason — the length guard is not what caught it: %v", err)
	}
}

// The companion: the same shape just under the limit has to be accepted, or
// the test above would pass for any address at all.
func TestValidate_acceptsALongButLegalAddress(t *testing.T) {
	local := strings.Repeat("a", 60)
	label := strings.Repeat("b", 60)
	address := local + "@" + label + "." + label + ".com"

	if len(address) > 254 {
		t.Fatalf("fixture is %d characters, it has to stay under 254", len(address))
	}
	if err := validate(address); err != nil {
		t.Fatalf("a long but legal address must be accepted: %v", err)
	}
}
