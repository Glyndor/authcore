// Package errs holds the sentinel errors and the wrapping error types shared
// by the email sub-packages. The email package re-exports the sentinels, so
// errors.Is keeps matching the same values for callers.
package errs

import "errors"

// ErrInvalidEmail signals that an address failed RFC 5321/5322 validation,
// or that Config.RejectPlusAddressing is set and the address contains a '+'
// in the local part.
var ErrInvalidEmail = errors.New("email: invalid address")

// ErrDomainNoMX signals that the domain exists but has no MX records,
// meaning it cannot receive email.
var ErrDomainNoMX = errors.New("email: domain has no MX records")

// ErrDomainUnresolvable signals that the DNS lookup failed due to a network
// error, timeout, or resolver unavailability.
var ErrDomainUnresolvable = errors.New("email: domain could not be resolved")

// Invalid wraps ErrInvalidEmail with a single specific reason so that
// both errors.Is(err, ErrInvalidEmail) and errors.Unwrap(err) work correctly.
func Invalid(reason error) error { return &emailViolation{reason: reason} }

// Unresolvable wraps ErrDomainUnresolvable preserving the underlying DNS
// error for logging while keeping errors.Is(err, ErrDomainUnresolvable) working.
func Unresolvable(cause error) error { return &domainUnresolvable{cause: cause} }

// NoMX wraps ErrDomainNoMX when the resolver authoritatively reports that no
// MX records exist for the domain (NXDOMAIN or NODATA, surfaced by Go's
// resolver as *net.DNSError with IsNotFound set). The cause is kept for
// logging; the sentinel comparison is preserved so callers' errors.Is checks
// still match.
func NoMX(cause error) error { return &noMXFromDNS{cause: cause} }

// emailViolation wraps ErrInvalidEmail with a single specific reason.
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
// that no MX records exist for the domain.
type noMXFromDNS struct{ cause error }

func (e *noMXFromDNS) Error() string {
	return ErrDomainNoMX.Error() + ": " + e.cause.Error()
}
func (e *noMXFromDNS) Is(t error) bool { return t == ErrDomainNoMX }
func (e *noMXFromDNS) Unwrap() error   { return e.cause }
