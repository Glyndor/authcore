package email

import "errors"

// ErrInvalidEmail signals that an address failed RFC 5321/5322 validation,
// or that Config.RejectPlusAddressing is set and the address contains a '+'
// in the local part.
//
// CLIENT-SAFE: the wrapped reason describes exactly which rule failed and is
// suitable for returning in a 400 response:
//
//	normalized, err := emailMod.ValidateAndNormalize(req.Email)
//	if err != nil {
//	    c.JSON(400, map[string]string{"error": errors.Unwrap(err).Error()})
//	    return
//	}
//
// Use errors.Is to check for this in calling code.
var ErrInvalidEmail = errors.New("email: invalid address")

// ErrDomainNoMX is CLIENT-SAFE: the domain exists but has no MX records,
// meaning it cannot receive email. Safe to return as a 400 response:
//
//	if errors.Is(err, email.ErrDomainNoMX) {
//	    c.JSON(400, map[string]string{"error": "email domain cannot receive messages"})
//	    return
//	}
var ErrDomainNoMX = errors.New("email: domain has no MX records")

// ErrDomainUnresolvable is INTERNAL: the DNS lookup failed due to a network
// error, timeout, or resolver unavailability. Do NOT block the user on this —
// log the error and let the request proceed:
//
//	if errors.Is(err, email.ErrDomainUnresolvable) {
//	    log.Warn("DNS check failed, skipping: %v", err)
//	    // continue — don't block the user
//	}
var ErrDomainUnresolvable = errors.New("email: domain could not be resolved")

// emailViolation wraps ErrInvalidEmail with a single specific reason so that
// both errors.Is(err, ErrInvalidEmail) and errors.Unwrap(err) work correctly.
type emailViolation struct{ reason error }

func (v *emailViolation) Error() string   { return ErrInvalidEmail.Error() + ": " + v.reason.Error() }
func (v *emailViolation) Is(t error) bool { return t == ErrInvalidEmail }
func (v *emailViolation) Unwrap() error   { return v.reason }

// domainUnresolvable wraps ErrDomainUnresolvable preserving the underlying
// DNS error for logging while keeping errors.Is(err, ErrDomainUnresolvable) working.
type domainUnresolvable struct{ cause error }

func (e *domainUnresolvable) Error() string {
	return ErrDomainUnresolvable.Error() + ": " + e.cause.Error()
}
func (e *domainUnresolvable) Is(t error) bool { return t == ErrDomainUnresolvable }
func (e *domainUnresolvable) Unwrap() error   { return e.cause }

// noMXFromDNS wraps ErrDomainNoMX when the resolver authoritatively reports
// that no MX records exist for the domain (NXDOMAIN or NODATA, surfaced by
// Go's resolver as *net.DNSError with IsNotFound set). The cause is kept for
// logging; the sentinel comparison is preserved so callers' errors.Is checks
// still match.
type noMXFromDNS struct{ cause error }

func (e *noMXFromDNS) Error() string {
	return ErrDomainNoMX.Error() + ": " + e.cause.Error()
}
func (e *noMXFromDNS) Is(t error) bool { return t == ErrDomainNoMX }
func (e *noMXFromDNS) Unwrap() error   { return e.cause }

// ErrInvalidConfig is returned by New and NewWithConfig when the provider is
// nil or has no logger.
var ErrInvalidConfig = errors.New("email: invalid config")
