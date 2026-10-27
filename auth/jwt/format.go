package jwt

import (
	"fmt"
	"log/slog"

	"github.com/Glyndor/authcore/internal/redactfmt"
)

// redactedName is the name the redacted renderings print for JWT.
const redactedName = "jwt.JWT"

// Compile-time proof that JWT controls its own formatting, held by pointer or
// by value.
var (
	_ fmt.Formatter  = JWT[struct{}]{}
	_ fmt.Formatter  = (*JWT[struct{}])(nil)
	_ fmt.Stringer   = (*JWT[struct{}])(nil)
	_ fmt.GoStringer = (*JWT[struct{}])(nil)
	_ slog.LogValuer = (*JWT[struct{}])(nil)
)

// Format renders the module as a fixed string for every verb. The value
// receiver covers a copy of the module as well as a pointer to it.
func (j JWT[T]) Format(f fmt.State, verb rune) { redactfmt.Format(f, verb, redactedName) }

// String returns a fixed description that carries no key material.
func (j *JWT[T]) String() string { return redactfmt.String(j == nil, redactedName) }

// GoString is the %#v form of String.
func (j *JWT[T]) GoString() string { return redactfmt.GoString(j == nil, redactedName) }

// LogValue keeps slog from reflecting over the module.
func (j *JWT[T]) LogValue() slog.Value { return redactfmt.LogValue(j == nil, redactedName) }
