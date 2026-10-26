package totp

import (
	"fmt"
	"log/slog"

	"github.com/Glyndor/authcore/internal/redactfmt"
)

// redactedName is the name the redacted renderings print for TOTP.
const redactedName = "totp.TOTP"

// Compile-time proof that TOTP controls its own formatting, held by pointer or
// by value.
var (
	_ fmt.Formatter  = TOTP{}
	_ fmt.Formatter  = (*TOTP)(nil)
	_ fmt.Stringer   = (*TOTP)(nil)
	_ fmt.GoStringer = (*TOTP)(nil)
	_ slog.LogValuer = (*TOTP)(nil)
)

// Format renders the module as a fixed string for every verb. The value
// receiver covers a copy of the module as well as a pointer to it.
func (t TOTP) Format(f fmt.State, verb rune) { redactfmt.Format(f, verb, redactedName) }

// String returns a fixed description that carries no key material.
func (t *TOTP) String() string { return redactfmt.String(t == nil, redactedName) }

// GoString is the %#v form of String.
func (t *TOTP) GoString() string { return redactfmt.GoString(t == nil, redactedName) }

// LogValue keeps slog from reflecting over the module.
func (t *TOTP) LogValue() slog.Value { return redactfmt.LogValue(t == nil, redactedName) }
