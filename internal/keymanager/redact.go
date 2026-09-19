package keymanager

import (
	"fmt"
	"io"
)

// redacted is the placeholder printed in place of any secret field.
const redacted = "REDACTED"

// Compile-time proof that *KeyManager controls its own formatting. Without
// these, fmt reflects over the struct and prints every field, unexported
// ones included.
var (
	_ fmt.Formatter  = (*KeyManager)(nil)
	_ fmt.Stringer   = (*KeyManager)(nil)
	_ fmt.GoStringer = (*KeyManager)(nil)
)

// Format renders the key manager without any secret material.
//
// Unexported fields stop a caller reaching the private key and the refresh
// secret through the type. They do not stop fmt, which reflects past
// exportedness: before this method existed, %v and %+v printed both secrets
// as decimal byte slices and %#v printed them in hex. A single diagnostic
// line such as log.Printf("%+v", ac.Keys()) put the Ed25519 signing key into
// log storage, and possession of that key is token forgery.
//
// fmt.Formatter takes precedence over every other formatting interface and
// applies to every verb, which is why the redaction lives here rather than in
// String alone: a String method would have left %#v leaking in hex. Verbs
// that make no sense for this type render as a Go %!verb error rather than
// falling back to reflection, because that fallback is the leak.
func (km *KeyManager) Format(f fmt.State, verb rune) {
	switch verb {
	case 'v':
		if f.Flag('#') {
			_, _ = io.WriteString(f, km.GoString())
			return
		}
		_, _ = io.WriteString(f, km.String())
	case 's', 'q':
		if verb == 'q' {
			_, _ = fmt.Fprintf(f, "%q", km.String())
			return
		}
		_, _ = io.WriteString(f, km.String())
	default:
		_, _ = fmt.Fprintf(f, "%%!%c(keymanager.KeyManager)", verb)
	}
}

// String describes the key manager by the two things that are safe to print:
// where its material lives and which signing key is active.
func (km *KeyManager) String() string {
	if km == nil {
		return "<nil>"
	}
	return fmt.Sprintf("keymanager.KeyManager{dir:%q, keyID:%q, privateKey:%s, publicKey:%s, refreshSecret:%s}",
		km.dir, km.keyID, redacted, redacted, redacted)
}

// GoString covers the %#v verb, which is a separate rendering path in fmt and
// prints byte slices in hex rather than decimal. A redaction test that looks
// for the secret in one encoding passes over it in the other, so both paths
// are redacted here and both are asserted in the tests.
func (km *KeyManager) GoString() string {
	if km == nil {
		return "(*keymanager.KeyManager)(nil)"
	}
	return fmt.Sprintf("&keymanager.KeyManager{dir:%q, keyID:%q, privateKey:%s, publicKey:%s, refreshSecret:%s}",
		km.dir, km.keyID, redacted, redacted, redacted)
}
