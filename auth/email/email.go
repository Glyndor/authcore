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
// Plus-addressing (`user+tag@example.com`) is accepted by default. A
// deployment that treats `(local, domain)` as the unique account key can
// opt in to [Config.RejectPlusAddressing] - this is a
// [configurable policy field](../docs/configuration.md#the-principle),
// not a security control. The structural rules above stay fixed.
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
// receive email. Results are cached per domain for [DefaultCacheTTL]
// (5 minutes by default) to avoid repeated lookups for the same domain.
// The Go stdlib LookupMX API does not surface DNS TTLs, so entries are
// held for the fixed [DefaultCacheTTL] regardless of the authority
// section of the response.
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
	"errors"
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

// mxResolver is the slice of net.Resolver that VerifyDomain depends on. A
// narrow interface keeps the production code against the stdlib type and
// lets tests swap in a deterministic stub without spinning up a fake DNS
// server.
type mxResolver interface {
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
}

// Email is the email validation and normalization module.
// Create one instance at startup via New and reuse it — it is safe for
// concurrent use after construction. It owns no background goroutine and
// needs no cleanup; like the other modules, you construct it and use it.
type Email struct {
	log                  authcore.Logger
	resolver             mxResolver
	cacheTTL             time.Duration
	mu                   sync.RWMutex
	cache                map[string]cacheEntry
	group                singleflight.Group
	rejectPlusAddressing bool // when true, ValidateAndNormalize rejects '+' in the local part
}

// New creates an Email module using the provider's logger.
// Equivalent to NewWithConfig(p, Config{}) - accepts the same plus-addressing
// behaviour as the existing module always has.
//
//	emailMod, err := email.New(auth)
//	if err != nil { ... }
func New(p authcore.Provider) (*Email, error) {
	return NewWithConfig(p, Config{})
}

// Config holds the email module's policy options.
//
// Today's behaviour is reproduced by the zero value, so callers that do not
// need to override anything can keep using New(p). NewWithConfig is the
// addition: it takes the policy explicitly.
type Config struct {
	// RejectPlusAddressing rejects addresses whose local part contains a
	// '+'. When false (the default), plus-addressing is accepted - the same
	// behaviour the module has always had.
	//
	// This is an account-uniqueness rule, not a security control. RFC 5233
	// defines plus-addressing so that user+anything@example.com and
	// user@example.com share one mailbox. Accepting it lets one mailbox own
	// N accounts: if your product treats (local, domain) as the unique key,
	// turn this on.
	RejectPlusAddressing bool
}

// NewWithConfig creates an Email module with an explicit Config.
//
// The zero Config{} reproduces the behaviour of New(p) - today's default.
//
//	emailMod, err := email.NewWithConfig(auth, email.Config{
//	    RejectPlusAddressing: true,
//	})
func NewWithConfig(p authcore.Provider, cfg Config) (*Email, error) {
	e := &Email{
		log:                  p.Logger(),
		resolver:             net.DefaultResolver,
		cacheTTL:             DefaultCacheTTL,
		cache:                make(map[string]cacheEntry),
		rejectPlusAddressing: cfg.RejectPlusAddressing,
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
	normalized, err := normalize(address)
	if err != nil {
		return "", err
	}
	if err := validate(normalized); err != nil {
		return "", err
	}
	// Plus-addressing is a policy rule applied AFTER structural validation,
	// so that an address which is structurally invalid for other reasons is
	// reported with the structural error first (more actionable for the
	// caller). The check itself is a single byte scan against the already
	// extracted local part: see ValidateAndNormalize implementation.
	if e.rejectPlusAddressing {
		atIdx := strings.LastIndexByte(normalized, '@')
		if atIdx > 0 && strings.IndexByte(normalized[:atIdx], '+') >= 0 {
			return "", &emailViolation{reason: fmt.Errorf("plus-addressing is not allowed")}
		}
	}
	return normalized, nil
}

// normalize lowercases the address, trims surrounding whitespace, and
// converts a Unicode (IDN) domain to its ASCII (punycode) form. Internal
// only — callers outside this package must use ValidateAndNormalize.
//
// Returns an error wrapping ErrInvalidEmail when the domain cannot be
// converted (a leading or trailing hyphen in a label, an underscore, a
// colon, or any other codepoint that IDNA forbids). The conversion failure
// must not fall through to the raw input: the downstream structural checks
// do not catch a leading-hyphen label, and a malformed name has no
// canonical form to store or query.
func normalize(address string) (string, error) {
	lower := strings.ToLower(strings.TrimSpace(address))
	atIdx := strings.LastIndexByte(lower, '@')
	if atIdx < 0 {
		// Addresses without an "@" fail validation regardless of IDN, so
		// leaving the input untouched here produces a clearer error path.
		return lower, nil
	}
	local, domain := lower[:atIdx], lower[atIdx+1:]
	ascii, err := idnaProfile.ToASCII(domain)
	if err != nil {
		return "", &emailViolation{reason: fmt.Errorf("domain %q is not a valid internationalised name: %w", domain, err)}
	}
	return local + "@" + ascii, nil
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
// Results are cached per domain for [DefaultCacheTTL] (5 minutes by default).
// Go's net.Resolver.LookupMX does not expose the DNS TTL, so entries are
// held for the fixed duration regardless of the authority section.
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
// avoid slowing down your registration endpoint. Concurrent callers for the
// same domain share a single DNS query through singleflight, and each
// caller's context still bounds its own wait, so a caller arriving with a
// shorter deadline than the in-flight lookup is not blocked past it:
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
	// Each caller selects on its own ctx.Done() so a short deadline on a
	// late-arriving caller does not block on the first caller's lookup.
	// DoChan returns a channel that closes exactly once with the shared
	// result; an early return on ctx.Done() abandons the channel for this
	// caller only, and the in-flight lookup completes for the others. The cache is populated inside the function
	// so a deadline-limited caller benefits from another caller's answer.
	ch := e.group.DoChan(domain, func() (any, error) {
		mxs, err := e.resolver.LookupMX(ctx, domain)
		if err != nil {
			var dnsErr *net.DNSError
			if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
				// Authoritative "no such host" or "no records of this type"
				// (NXDOMAIN or NODATA for MX): the resolver answered with a
				// final answer, not a transport error. Classify this as a
				// definitive no-MX result and cache it with the normal TTL
				// so subsequent calls do not retry the lookup.
				entry := cacheEntry{hasMX: false, expiresAt: time.Now().Add(e.cacheTTL)}
				e.store(domain, entry)
				return nil, &noMXFromDNS{cause: err}
			}
			e.store(domain, cacheEntry{dnsFailure: true, expiresAt: time.Now().Add(30 * time.Second)})
			return nil, &domainUnresolvable{cause: err}
		}
		entry := cacheEntry{hasMX: hasRealMX(mxs), expiresAt: time.Now().Add(e.cacheTTL)}
		e.store(domain, entry)
		return entry, nil
	})
	select {
	case <-ctx.Done():
		return ctx.Err()
	case r := <-ch:
		if r.Err != nil {
			return r.Err
		}
		return entryErr(r.Val.(cacheEntry))
	}
}

// hasRealMX reports whether the slice from LookupMX represents a domain
// that accepts mail. A single record whose host is "." or "" is a "null MX"
// (RFC 7505 section 3): the domain explicitly states it does not accept
// mail, regardless of any other records a misconfigured resolver might
// also return. A non-null single record, or any slice with at least one
// non-null record, is a real MX.
func hasRealMX(mxs []*net.MX) bool {
	if len(mxs) == 0 {
		return false
	}
	if len(mxs) == 1 && (mxs[0].Host == "." || mxs[0].Host == "") {
		return false
	}
	return true
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
