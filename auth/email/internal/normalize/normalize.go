// Package normalize brings an email address to its canonical stored form.
package normalize

import (
	"fmt"
	"strings"

	"golang.org/x/net/idna"

	"github.com/Glyndor/authcore/auth/email/internal/errs"
	"github.com/Glyndor/authcore/auth/email/internal/localpart"
)

// idnaProfile is configured once and reused because the profile value is
// immutable and its internal tables are allocated only once.
// Lookup is the strictest profile that still tolerates TR46 transitional
// processing, matching what a browser's URL bar does when resolving a host.
var idnaProfile = idna.Lookup

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
	ascii, err := idnaProfile.ToASCII(domain)
	if err != nil {
		return "", errs.Invalid(fmt.Errorf("domain %q is not a valid internationalised name: %w", domain, err))
	}
	return local + "@" + ascii, nil
}
