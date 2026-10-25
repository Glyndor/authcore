// Package redact renders the key manager for fmt without any secret material:
// the verb dispatch behind fmt.Formatter and the two safe descriptions. The
// facade type stays in the keymanager package and delegates here, so the
// rules about what may be printed live in one place and in one file.
package redact

import (
	"fmt"
	"io"
)

// Placeholder is printed in place of any secret field.
const Placeholder = "REDACTED"

// Format writes the rendering fmt asked for. str and goStr produce the %v/%s/%q
// and %#v descriptions; they are functions so a nil receiver can answer for
// itself. Verbs that make no sense for the type render as a Go %!verb error
// rather than falling back to reflection, because that fallback is the leak.
func Format(f fmt.State, verb rune, str, goStr func() string) {
	switch verb {
	case 'v':
		if f.Flag('#') {
			_, _ = io.WriteString(f, goStr())
			return
		}
		_, _ = io.WriteString(f, str())
	case 's', 'q':
		if verb == 'q' {
			_, _ = fmt.Fprintf(f, "%q", str())
			return
		}
		_, _ = io.WriteString(f, str())
	default:
		_, _ = fmt.Fprintf(f, "%%!%c(keymanager.KeyManager)", verb)
	}
}

// Describe names the two things that are safe to print, where the material
// lives and which signing key is active, and marks every secret field as
// redacted. goSyntax selects the %#v form, which is a separate rendering path
// in fmt.
func Describe(goSyntax bool, dir, keyID string) string {
	prefix := "keymanager.KeyManager"
	if goSyntax {
		prefix = "&" + prefix
	}
	return fmt.Sprintf("%s{dir:%q, keyID:%q, privateKey:%s, publicKey:%s, refreshSecret:%s}",
		prefix, dir, keyID, Placeholder, Placeholder, Placeholder)
}
