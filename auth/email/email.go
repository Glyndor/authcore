package email

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/email/internal/errs"
	"github.com/Glyndor/authcore/auth/email/internal/mx"
	"github.com/Glyndor/authcore/auth/email/internal/normalize"
	"github.com/Glyndor/authcore/auth/email/internal/syntax"
)

// DefaultCacheTTL is the maximum duration a domain MX lookup result is cached.
// Tune this value if your workload has strict freshness requirements.
const DefaultCacheTTL = 5 * time.Minute

// Email is the email validation and normalization module.
// Create one instance at startup via New and reuse it — it is safe for
// concurrent use after construction. It owns no background goroutine and
// needs no cleanup; like the other modules, you construct it and use it.
type Email struct {
	log                  authcore.Logger
	mx                   *mx.Verifier
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

// NewWithConfig creates an Email module with an explicit Config.
//
// The zero Config{} reproduces the behaviour of New(p) - today's default.
//
//	emailMod, err := email.NewWithConfig(auth, email.Config{
//	    RejectPlusAddressing: true,
//	})
func NewWithConfig(p authcore.Provider, cfg Config) (*Email, error) {
	// A nil provider or logger used to panic (#406 fixed four other modules
	// and not this one, found 2026-09-25).
	if p == nil {
		return nil, fmt.Errorf("%w: provider is nil", ErrInvalidConfig)
	}
	if p.Logger() == nil {
		return nil, fmt.Errorf("%w: provider.Logger() returned nil", ErrInvalidConfig)
	}
	e := &Email{
		log:                  p.Logger(),
		mx:                   mx.New(net.DefaultResolver, DefaultCacheTTL),
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
	normalized, err := normalize.Address(address)
	if err != nil {
		return "", err
	}
	if err := syntax.Validate(normalized); err != nil {
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
			return "", errs.Invalid(fmt.Errorf("plus-addressing is not allowed"))
		}
	}
	return normalized, nil
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
//	[ErrInvalidEmail]       : the domain exceeds DNS size limits, so it was not looked up
//
// ctx bounds how long this caller waits. Use a short timeout (1–3 s) to avoid
// slowing down your registration endpoint. Concurrent callers for the same
// domain share a single DNS query through singleflight; the query itself runs
// under the module's own 10-second bound rather than any one caller's
// context, so a caller that gives up or disconnects neither blocks the others
// nor decides their answer:
//
//	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
//	defer cancel()
//	if err := emailMod.VerifyDomain(ctx, normalized); errors.Is(err, email.ErrDomainNoMX) {
//	    c.JSON(400, map[string]string{"error": "email domain cannot receive messages"})
//	    return
//	}
func (e *Email) VerifyDomain(ctx context.Context, address string) error {
	return e.mx.Verify(ctx, address)
}
