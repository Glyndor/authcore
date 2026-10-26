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
	// Lowercasing can leave a sequence that composes (a capital followed by
	// combining marks), and composing can expose another case mapping, so the
	// two steps repeat until the spelling stops changing. Without that, the
	// stored form was not a fixed point of this function.
	s := norm.NFC.String(local)
	for range maxPasses {
		if err := refuseUnsafe(s); err != nil {
			return "", err
		}
		next := norm.NFC.String(strings.ToLower(s))
		if next == s {
			return s, nil
		}
		s = next
	}
	return "", errs.Invalid(fmt.Errorf("local part has no stable canonical form"))
}

// maxPasses bounds the lowercase-and-compose loop; every input measured settles
// in two.
const maxPasses = 4

// refuseUnsafe refuses the characters that must not reach a stored address.
func refuseUnsafe(s string) error {
	for _, r := range s {
		switch {
		case unicode.Is(unicode.Cc, r), unicode.Is(unicode.Cf, r),
			unicode.Is(unicode.Zl, r), unicode.Is(unicode.Zp, r),
			unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r):
			return errs.Invalid(fmt.Errorf("local part holds an invisible or control character %U", r))
		case r >= utf8.RuneSelf && unicode.IsSpace(r):
			return errs.Invalid(fmt.Errorf("local part holds an invisible or control character %U", r))
		case r >= utf8.RuneSelf && unicode.ToLower(r) < utf8.RuneSelf:
			return errs.Invalid(fmt.Errorf("local part holds %U, which lowercases to an ASCII letter", r))
		}
	}
	return nil
}
