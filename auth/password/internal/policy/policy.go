// Package policy checks a plaintext password against the length, character
// class and printable-character rules of the password module.
package policy

import (
	"errors"
	"fmt"
	"unicode"
	"unicode/utf8"
)

// ErrNonPrintable is the reason Check returns for a plaintext holding a
// character that is not printable.
var ErrNonPrintable = errors.New("must contain only printable characters")

// Rules is the policy Check enforces. The Require fields are plain values:
// the caller resolves whatever optional form its configuration uses.
type Rules struct {
	MinLength, MaxLength                                    int
	RequireUpper, RequireLower, RequireDigit, RequireSymbol bool
}

// Check validates plaintext against the policy encoded in cfg.
// It runs in O(n) with a single pass and no memory allocations.
//
// Length is measured in Unicode characters (runes), not bytes, so a
// multibyte passphrase is counted the way a user perceives it: a 4-character
// CJK password is 4 characters, not 12 bytes.
//
// The error messages quote cfg.MinLength and cfg.MaxLength, so the caller
// sees the bound they actually configured.
//
// Keep the printable check ahead of the classification and outside cfg. It is
// not a product rule a caller can turn off: until #347 a NUL appended to
// "Abcdefghijk1" was what made it pass, got hashed, and verified.
func Check(plaintext string, cfg Rules) error {
	count := utf8.RuneCountInString(plaintext)
	if count < cfg.MinLength {
		return fmt.Errorf("must be at least %d characters", cfg.MinLength)
	}
	if count > cfg.MaxLength {
		return fmt.Errorf("must be at most %d characters", cfg.MaxLength)
	}

	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, r := range plaintext {
		if !isPrintable(r) {
			return ErrNonPrintable
		}
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		case isSpecial(r):
			hasSpecial = true
		}
		// No default arm on purpose. A printable rune outside the four classes
		// (a letter without case such as a CJK ideograph, a combining mark, a
		// number that is not a decimal digit) is allowed and satisfies nothing.
	}

	switch {
	case cfg.RequireUpper && !hasUpper:
		return fmt.Errorf("must contain at least one uppercase letter")
	case cfg.RequireLower && !hasLower:
		return fmt.Errorf("must contain at least one lowercase letter")
	case cfg.RequireDigit && !hasDigit:
		return fmt.Errorf("must contain at least one digit")
	case cfg.RequireSymbol && !hasSpecial:
		return fmt.Errorf("must contain at least one special character")
	}
	return nil
}

// isPrintable reports whether r may appear in a password at all.
//
// unicode.IsPrint is true for letters, marks, numbers, punctuation, symbols
// and the ASCII space, and false for control characters, format characters
// such as the zero-width joiner, every other space, and unassigned code
// points.
//
// U+FFFD needs its own clause. It is category So, so IsPrint accepts it, and
// it is what range yields for a byte that is not valid UTF-8. Measured before
// this check existed: "Abcdefghijk1\xff" passed the default policy with the
// stray byte counted as its special character.
func isPrintable(r rune) bool {
	if r == utf8.RuneError || !unicode.IsPrint(r) {
		return false
	}
	// IsPrint admits code points that render as nothing: the Hangul fillers
	// and the other default-ignorable letters and marks (U+115F, U+3164,
	// U+FFA0, U+034F among them), and U+2800 BRAILLE PATTERN BLANK, a symbol.
	// Measured 2026-09-25: "Abcdefghijk1" + U+2800 satisfied RequireSymbol
	// with a character the user cannot see, the lockout #347 describes.
	return r != 0x2800 && !unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r)
}

// isSpecial reports whether r satisfies RequireSymbol: Unicode punctuation
// (category P), Unicode symbols (category S), and the ASCII space.
//
// The space stays in the class because it always counted, OWASP lists it
// among the password special characters, and dropping it would start
// rejecting passphrases written as spaced words.
func isSpecial(r rune) bool {
	return r == ' ' || unicode.IsPunct(r) || unicode.IsSymbol(r)
}
