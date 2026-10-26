package apikey

import (
	"fmt"
	"log/slog"

	"github.com/Glyndor/authcore/internal/redactfmt"
)

// redactedName is the name the redacted renderings print for APIKey.
const redactedName = "apikey.APIKey"

// Compile-time proof that APIKey controls its own formatting, held by pointer or
// by value.
var (
	_ fmt.Formatter  = APIKey{}
	_ fmt.Formatter  = (*APIKey)(nil)
	_ fmt.Stringer   = (*APIKey)(nil)
	_ fmt.GoStringer = (*APIKey)(nil)
	_ slog.LogValuer = (*APIKey)(nil)
)

// Format renders the module as a fixed string for every verb. The value
// receiver covers a copy of the module as well as a pointer to it.
func (k APIKey) Format(f fmt.State, verb rune) { redactfmt.Format(f, verb, redactedName) }

// String returns a fixed description that carries no key material.
func (k *APIKey) String() string { return redactfmt.String(k == nil, redactedName) }

// GoString is the %#v form of String.
func (k *APIKey) GoString() string { return redactfmt.GoString(k == nil, redactedName) }

// LogValue keeps slog from reflecting over the module.
func (k *APIKey) LogValue() slog.Value { return redactfmt.LogValue(k == nil, redactedName) }
