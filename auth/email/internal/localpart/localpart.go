// Package localpart canonicalises the local part of an email address.
package localpart

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"github.com/Glyndor/authcore/auth/email/internal/errs"
)

// Canonical returns the one canonical spelling of a local part: NFC,
// then lowercased. Until 2026-09-25 the local part was lowercased as typed,
// so one mailbox had two canonical forms (precomposed and decomposed
// accents), two mailboxes could share one (U+212A KELVIN SIGN lowercases to
// "k", U+0130 to "i"), and control, format and line-separator characters
// travelled into the stored value. Each of those is refused now; the ASCII
// controls were already refused by net/mail. A byte sequence that is not valid
// UTF-8 is refused too: lowercasing rewrote every bad byte as U+FFFD, so
// distinct inputs shared one canonical form.
func Canonical(local string) (string, error) {
	if !utf8.ValidString(local) {
		return "", errs.Invalid(fmt.Errorf("local part is not valid UTF-8"))
	}
	local = norm.NFC.String(local)
	for _, r := range local {
		switch {
		case unicode.Is(unicode.Cc, r), unicode.Is(unicode.Cf, r),
			unicode.Is(unicode.Zl, r), unicode.Is(unicode.Zp, r),
			unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r):
			return "", errs.Invalid(fmt.Errorf("local part holds an invisible or control character %U", r))
		case r >= utf8.RuneSelf && unicode.ToLower(r) < utf8.RuneSelf:
			return "", errs.Invalid(fmt.Errorf("local part holds %U, which lowercases to an ASCII letter", r))
		}
	}
	return strings.ToLower(local), nil
}
