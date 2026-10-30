package email

import (
	"errors"

	"github.com/Glyndor/authcore/auth/email/internal/errs"
)

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
var ErrInvalidEmail = errs.ErrInvalidEmail

// ErrDomainNoMX is CLIENT-SAFE: the domain has no MX records or does not
// exist (the resolver answered NXDOMAIN or NODATA), meaning it cannot receive
// email. Safe to return as a 400 response:
//
//	if errors.Is(err, email.ErrDomainNoMX) {
//	    c.JSON(400, map[string]string{"error": "email domain cannot receive messages"})
//	    return
//	}
var ErrDomainNoMX = errs.ErrDomainNoMX

// ErrDomainUnresolvable is INTERNAL: the DNS lookup failed due to a network
// error, timeout, or resolver unavailability. Do NOT block the user on this —
// log the error and let the request proceed:
//
//	if errors.Is(err, email.ErrDomainUnresolvable) {
//	    log.Warn("DNS check failed, skipping: %v", err)
//	    // continue — don't block the user
//	}
var ErrDomainUnresolvable = errs.ErrDomainUnresolvable

// ErrInvalidConfig is returned by New and NewWithConfig when the provider is
// nil or has no logger.
var ErrInvalidConfig = errors.New("email: invalid config")
