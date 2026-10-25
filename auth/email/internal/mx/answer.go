package mx

import (
	"net"

	"github.com/Glyndor/authcore/auth/email/internal/errs"
)

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

// entryErr converts a cache entry into the appropriate sentinel error.
func entryErr(entry cacheEntry) error {
	if entry.dnsFailure {
		return errs.ErrDomainUnresolvable
	}
	if !entry.hasMX {
		return errs.ErrDomainNoMX
	}
	return nil
}
