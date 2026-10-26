package credential

import (
	"fmt"
	"log/slog"

	"github.com/Glyndor/authcore/internal/redactfmt"
)

// redactedName is the name the redacted renderings print for Credential.
const redactedName = "credential.Credential"

// Compile-time proof that Credential controls its own formatting, held by pointer or
// by value.
var (
	_ fmt.Formatter  = Credential{}
	_ fmt.Formatter  = (*Credential)(nil)
	_ fmt.Stringer   = (*Credential)(nil)
	_ fmt.GoStringer = (*Credential)(nil)
	_ slog.LogValuer = (*Credential)(nil)
)

// Format renders the module as a fixed string for every verb. The value
// receiver covers a copy of the module as well as a pointer to it.
func (c Credential) Format(f fmt.State, verb rune) { redactfmt.Format(f, verb, redactedName) }

// String returns a fixed description that carries no key material.
func (c *Credential) String() string { return redactfmt.String(c == nil, redactedName) }

// GoString is the %#v form of String.
func (c *Credential) GoString() string { return redactfmt.GoString(c == nil, redactedName) }

// LogValue keeps slog from reflecting over the module.
func (c *Credential) LogValue() slog.Value { return redactfmt.LogValue(c == nil, redactedName) }
