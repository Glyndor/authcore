// Package normalize brings an email address to its canonical stored form.
package normalize

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/idna"

	"github.com/Glyndor/authcore/auth/email/internal/errs"
	"github.com/Glyndor/authcore/auth/email/internal/localpart"
)

// idnaProfile is configured once and reused because the profile value is
// immutable and its internal tables are allocated only once.
// Lookup is the strictest profile that still tolerates TR46 transitional
// processing, matching what a browser's URL bar does when resolving a host.
var idnaProfile = idna.Lookup

// maxAddressBytes bounds the input before any Unicode processing. It is well
// above the longest address that can be valid and low enough that IDNA over it
// costs a few milliseconds.
const maxAddressBytes = 2048

// Address lowercases the address, trims surrounding whitespace, and
// converts a Unicode (IDN) domain to its ASCII (punycode) form. Internal
// only — callers outside this package must use ValidateAndNormalize.
//
// Returns an error wrapping ErrInvalidEmail when the domain cannot be
// converted (a leading or trailing hyphen in a label, an underscore, a
// colon, or any other codepoint that IDNA forbids). The conversion failure
// must not fall through to the raw input: the downstream structural checks
// do not catch a leading-hyphen label, and a malformed name has no
// canonical form to store or query.
func Address(address string) (string, error) {
	trimmed := strings.TrimSpace(address)
	// The punycode step of IDNA costs time quadratic in the number of distinct
	// code points, and the 254 byte limit of syntax.Validate runs after it. A
	// body of a few hundred kilobytes of distinct characters kept a core busy
	// for minutes, then was refused. An address that could pass is far below
	// this: 254 ASCII characters is at most four times as many UTF-8 bytes in
	// the domain, and the local part adds a few hundred more.
	if len(trimmed) > maxAddressBytes {
		return "", errs.Invalid(fmt.Errorf("must be at most 254 characters"))
	}
	atIdx := strings.LastIndexByte(trimmed, '@')
	if atIdx < 0 {
		// Addresses without an "@" fail validation regardless of IDN, so
		// leaving the input untouched here produces a clearer error path.
		return strings.ToLower(trimmed), nil
	}
	local, err := localpart.Canonical(trimmed[:atIdx])
	if err != nil {
		return "", err
	}
	// The domain goes to IDNA as typed: the Lookup profile applies the UTS #46
	// case mapping itself. Lowercasing first with strings.ToLower used Go's
	// simple case table instead, which turned U+0130 into an ASCII "i" and
	// let the capital Georgian letters and U+04C0 through as their small forms,
	// all of which UTS #46 maps differently or disallows.
	domain := trimmed[atIdx+1:]
	// IDNA reads an invalid UTF-8 byte as U+FFFD and converts it, so every such
	// byte gave the same ASCII name ("xn--zn7c") that the next validation then
	// refused. The local part already refuses invalid UTF-8 for the same reason.
	if !utf8.ValidString(domain) {
		return "", errs.Invalid(fmt.Errorf("domain is not valid UTF-8"))
	}
	ascii, err := idnaProfile.ToASCII(domain)
	if err != nil {
		return "", errs.Invalid(fmt.Errorf("domain is not a valid internationalised name"))
	}
	// A name whose ASCII form IDNA then refuses has no canonical form: the
	// stored value would be rejected the next time it went through here.
	if again, err := idnaProfile.ToASCII(ascii); err != nil || again != ascii {
		return "", errs.Invalid(fmt.Errorf("domain has no stable internationalised form"))
	}
	return local + "@" + ascii, nil
}
