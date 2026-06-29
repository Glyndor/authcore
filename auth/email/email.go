// Package email provides email address validation and normalization for authcore.
//
// Validation follows RFC 5321 and RFC 5322 rules:
//   - Total length 1–254 characters
//   - Exactly one @ separating a non-empty local part and domain
//   - Local part ≤ 64 characters
//   - Domain contains at least one dot; no leading, trailing, or consecutive dots
//   - Each domain label is 1–63 characters
//
// Internationalised domain names (IDN) are supported: a Unicode domain such
// as "münchen.de" is converted to its ASCII punycode form ("xn--mnchen-3ya.de")
// during normalisation, matching what DNS actually resolves. Store the
// canonical ASCII form in your database so lookups are deterministic.
//
// The single entry point is [Email.ValidateAndNormalize] — it normalizes
// (lowercase + trim + punycode) and validates in one step, returning the
// canonical form.
// Always store and query emails using this canonical form:
//
//	emailMod, _ := email.New(auth)
//
//	// Registration
//	normalized, err := emailMod.ValidateAndNormalize(req.Email)
//	if err != nil {
//	    c.JSON(400, map[string]string{"error": errors.Unwrap(err).Error()})
//	    return
//	}
//	db.StoreUser(normalized, ...)
//
//	// Login lookup — same call, same canonical form, consistent results
//	normalized, err = emailMod.ValidateAndNormalize(req.Email)
//	if err != nil { ... }
//	user := db.FindByEmail(normalized)
//
// # Domain MX verification
//
// VerifyDomain performs an optional DNS MX lookup to confirm the domain can
// receive email. Results are cached per domain using the DNS TTL (capped at
// [DefaultCacheTTL]) to avoid repeated lookups for the same domain.
// This check is network I/O — always call it after ValidateAndNormalize and
// handle [ErrDomainUnresolvable] as a soft failure:
//
//	err = emailMod.VerifyDomain(ctx, normalized)
//	if errors.Is(err, email.ErrDomainNoMX) {
//	    c.JSON(400, map[string]string{"error": "email domain cannot receive messages"})
//	    return
//	}
//	if errors.Is(err, email.ErrDomainUnresolvable) {
//	    log.Warn("DNS check unavailable: %v", err) // do not block the user
//	}
package email

import (
	"context"
	"fmt"
	"net"
	"net/mail"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/idna"
	"golang.org/x/sync/singleflight"

	"github.com/Glyndor/authcore"
)

// idnaProfile is configured once and reused because the profile value is
// immutable and its internal tables are allocated only once.
// Lookup is the strictest profile that still tolerates TR46 transitional
// processing, matching what a browser's URL bar does when resolving a host.
var idnaProfile = idna.Lookup

// DefaultCacheTTL is the maximum duration a domain MX lookup result is cached.
// Tune this value if your workload has strict freshness requirements.
const DefaultCacheTTL = 5 * time.Minute

// maxCacheSize is the maximum number of domains held in the cache at once.
// If the cache is full when a new result arrives, it is silently dropped —
// the next request will query DNS again. Background eviction keeps the cache
// below this limit under normal operation.
const maxCacheSize = 10_000

// cacheEntry holds the result of a single MX lookup.
type cacheEntry struct {
	hasMX      bool
	dnsFailure bool // true = DNS error, false = confirmed result
	expiresAt  time.Time
}

// Email is the email validation and normalization module.
// Create one instance at startup via New and reuse it — it is safe for
// concurrent use after construction. It owns no background goroutine and
// needs no cleanup; like the other modules, you construct it and use it.
type Email struct {
	log      authcore.Logger
	resolver *net.Resolver
	cacheTTL time.Duration
	mu       sync.RWMutex
	cache    map[string]cacheEntry
	group    singleflight.Group
}

// New creates an Email module using the provider's logger.
//
//	emailMod, err := email.New(auth)
//	if err != nil { ... }
func New(p authcore.Provider) (*Email, error) {
	e := &Email{
		log:      p.Logger(),
		resolver: net.DefaultResolver,
		cacheTTL: DefaultCacheTTL,
		cache:    make(map[string]cacheEntry),
	}
	e.log.Info("email: module initialised")
	return e, nil
}

// Close is a no-op retained for backward compatibility.
//
// The module no longer runs a background goroutine: the MX cache evicts
// expired entries lazily when it fills (see store), and reads always ignore
// expired entries. Nothing needs to be released, so calling Close is optional
// and always safe — including multiple times and from multiple goroutines.
func (e *Email) Close() {}

// evictExpired deletes all expired entries from the cache, taking the write
// lock itself.
func (e *Email) evictExpired() {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := time.Now()
	for k, v := range e.cache {
		if now.After(v.expiresAt) {
			delete(e.cache, k)
		}
	}
}

// Name implements authcore.Module.
func (e *Email) Name() string { return "email" }

// ValidateAndNormalize is the single entry point for email validation.
// It lowercases, trims surrounding whitespace, and validates the address
// against RFC 5321 / RFC 5322 rules in one atomic step.
//
// Always use this function — never normalize and validate separately.
// The returned string is the canonical form that must be stored and queried:
//
//	normalized, err := emailMod.ValidateAndNormalize(req.Email)
//	if err != nil {
//	    // errors.Unwrap(err).Error() contains the specific rule that failed.
//	    c.JSON(400, map[string]string{"error": errors.Unwrap(err).Error()})
//	    return
//	}
//	db.StoreUser(normalized, ...) // always lowercase, trimmed, validated
func (e *Email) ValidateAndNormalize(address string) (string, error) {
	// Normalize first so validation sees the canonical form.
	// Storing the normalized form ensures consistent lookups:
	// "USER@EXAMPLE.COM" and "user@example.com" resolve to the same record.
	normalized := normalize(address)
	if err := validate(normalized); err != nil {
		return "", err
	}
	return normalized, nil
}

// normalize lowercases the address, trims surrounding whitespace, and
// converts a Unicode (IDN) domain to its ASCII (punycode) form. Internal
// only — callers outside this package must use ValidateAndNormalize.
//
// If the domain cannot be converted (for example it contains a disallowed
// codepoint), the original lowercased + trimmed string is returned. The
// downstream validator will then reject it with a clear "invalid format"
// error.
func normalize(address string) string {
	lower := strings.ToLower(strings.TrimSpace(address))
	atIdx := strings.LastIndexByte(lower, '@')
	if atIdx < 0 {
		// Addresses without an "@" fail validation regardless of IDN, so
		// leaving the input untouched here produces a clearer error path.
		return lower
	}
	local, domain := lower[:atIdx], lower[atIdx+1:]
	ascii, err := idnaProfile.ToASCII(domain)
	if err != nil {
		return lower
	}
	return local + "@" + ascii
}

// validate checks address against RFC 5321 / RFC 5322 rules.
// It uses net/mail for syntax and then applies stricter structural checks.
func validate(address string) error {
	if len(address) == 0 {
		return &emailViolation{reason: fmt.Errorf("must not be empty")}
	}
	if len(address) > 254 {
		return &emailViolation{reason: fmt.Errorf("must be at most 254 characters")}
	}

	// net/mail.ParseAddress handles RFC 5322 syntax (quoted strings, comments, etc.).
	parsed, err := mail.ParseAddress(address)
	if err != nil {
		return &emailViolation{reason: fmt.Errorf("invalid format")}
	}

	// Reject display names like "Ana García <ana@example.com>".
	// EqualFold is intentional: net/mail may normalize domain case, so a
	// direct == would reject valid addresses when Validate is called without
	// prior normalization (e.g. "User@EXAMPLE.COM" vs "User@example.com").
	if !strings.EqualFold(address, parsed.Address) {
		return &emailViolation{reason: fmt.Errorf("invalid format")}
	}

	atIdx := strings.LastIndexByte(parsed.Address, '@')
	local := parsed.Address[:atIdx]
	domain := parsed.Address[atIdx+1:]

	if len(local) > 64 {
		return &emailViolation{reason: fmt.Errorf("local part must be at most 64 characters")}
	}

	// Reject address literals like "user@[192.168.1.1]" or "user@[IPv6:...]".
	// net/mail accepts them, but they are almost never wanted in an account
	// system, cannot be MX-verified, and would otherwise slip through the
	// dot/label checks below (the bracketed octets look like labels).
	if strings.HasPrefix(domain, "[") {
		return &emailViolation{reason: fmt.Errorf("domain must not be an address literal")}
	}

	// Domain: at least one dot, no leading/trailing/consecutive dots,
	// each label 1–63 characters.
	hasDot := false
	labelLen := 0
	for i := 0; i < len(domain); i++ {
		if domain[i] == '.' {
			if labelLen == 0 {
				return &emailViolation{reason: fmt.Errorf("domain must not start with or contain consecutive dots")}
			}
			hasDot = true
			labelLen = 0
		} else {
			labelLen++
			if labelLen > 63 {
				return &emailViolation{reason: fmt.Errorf("each domain label must be at most 63 characters")}
			}
		}
	}
	if !hasDot {
		return &emailViolation{reason: fmt.Errorf("domain must contain at least one dot")}
	}
	if labelLen == 0 {
		return &emailViolation{reason: fmt.Errorf("domain must not end with a dot")}
	}

	return nil
}

// VerifyDomain performs a DNS MX lookup to confirm that the email's domain
// can receive messages. It is an optional, network-bound complement to
// ValidateAndNormalize — call it only after format validation succeeds.
//
// Results are cached per domain for the duration of the DNS TTL, capped at
// [DefaultCacheTTL], to avoid repeated lookups for the same domain.
//
// The cache and the single-flight de-duplication bound repeated and concurrent
// lookups for the SAME domain, but each uncached distinct domain still costs one
// outbound DNS query — a flood of unique domains is not bounded here. Rate-limit
// the endpoint that calls VerifyDomain (registration) so an attacker cannot turn
// it into a DNS-amplification vector.
//
// On success it returns nil.
// On failure it returns one of:
//
//	[ErrDomainNoMX]         — domain exists but has no MX records (CLIENT-SAFE, return 400)
//	[ErrDomainUnresolvable] — DNS lookup failed; treat as a soft failure and do not block the user
//
// ctx controls the deadline of the DNS query. Use a short timeout (1–3 s) to
// avoid slowing down your registration endpoint:
//
//	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
//	defer cancel()
//	if err := emailMod.VerifyDomain(ctx, normalized); errors.Is(err, email.ErrDomainNoMX) {
//	    c.JSON(400, map[string]string{"error": "email domain cannot receive messages"})
//	    return
//	}
func (e *Email) VerifyDomain(ctx context.Context, address string) error {
	domain := domainOf(address)
	if domain == "" {
		return ErrDomainNoMX
	}

	// Fast path: valid cache hit.
	if entry, ok := e.cached(domain); ok {
		return entryErr(entry)
	}

	// Slow path: deduplicated DNS lookup.
	// singleflight.Group ensures that N concurrent callers for the same domain
	// fire exactly one DNS query; all share the result. This prevents thundering
	// herd when a cache entry expires under high concurrency.
	//
	// Note: the ctx used is the one from the call that triggers the lookup.
	// Other callers sharing the result are not affected by their own contexts
	// while waiting — this is a known singleflight trade-off.
	v, dnsErr, _ := e.group.Do(domain, func() (any, error) {
		mxs, err := e.resolver.LookupMX(ctx, domain)
		if err != nil {
			e.store(domain, cacheEntry{dnsFailure: true, expiresAt: time.Now().Add(30 * time.Second)})
			return nil, &domainUnresolvable{cause: err}
		}
		entry := cacheEntry{hasMX: len(mxs) > 0, expiresAt: time.Now().Add(e.cacheTTL)}
		e.store(domain, entry)
		return entry, nil
	})
	if dnsErr != nil {
		return dnsErr
	}
	return entryErr(v.(cacheEntry))
}

// cached returns the cache entry for domain if it exists and has not expired.
func (e *Email) cached(domain string) (cacheEntry, bool) {
	e.mu.RLock()
	entry, ok := e.cache[domain]
	e.mu.RUnlock()
	return entry, ok && time.Now().Before(entry.expiresAt)
}

// store writes entry into the cache under write lock. When the cache is full,
// it first drops expired entries to make room (lazy eviction — this is what
// replaces the old background goroutine); if it is still full afterwards the
// entry is dropped and the next lookup retries DNS.
func (e *Email) store(domain string, entry cacheEntry) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.cache) >= maxCacheSize {
		now := time.Now()
		for k, v := range e.cache {
			if now.After(v.expiresAt) {
				delete(e.cache, k)
			}
		}
	}
	if len(e.cache) < maxCacheSize {
		e.cache[domain] = entry
	}
}

// entryErr converts a cache entry into the appropriate sentinel error.
func entryErr(entry cacheEntry) error {
	if entry.dnsFailure {
		return ErrDomainUnresolvable
	}
	if !entry.hasMX {
		return ErrDomainNoMX
	}
	return nil
}

// domainOf extracts the domain part of a normalized email address.
// Returns "" if address contains no '@'.
func domainOf(address string) string {
	i := strings.LastIndexByte(address, '@')
	if i < 0 {
		return ""
	}
	return address[i+1:]
}
