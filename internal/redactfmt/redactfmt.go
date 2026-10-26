// Package redactfmt gives the module types a fixed, secret-free rendering for
// fmt, log and slog. A module type delegates its fmt.Formatter, fmt.Stringer,
// fmt.GoStringer and slog.LogValuer methods here, so what may be printed is
// decided in one place.
package redactfmt

import (
	"fmt"
	"io"
	"log/slog"
)

// Marker stands in for every field of a redacted type.
const Marker = "redacted"

// String describes a value of the named type. A nil pointer renders as
// "<nil>", matching what fmt prints for one.
func String(isNil bool, name string) string {
	if isNil {
		return "<nil>"
	}
	return name + "{" + Marker + "}"
}

// GoString is the %#v counterpart of String.
func GoString(isNil bool, name string) string {
	if isNil {
		return "(*" + name + ")(nil)"
	}
	return "&" + name + "{" + Marker + "}"
}

// LogValue is the slog rendering of a value of the named type.
func LogValue(isNil bool, name string) slog.Value {
	return slog.StringValue(String(isNil, name))
}

// Format writes the rendering fmt asked for. It is meant for a value receiver,
// so that a copy of the type is covered as well as a pointer to it. Verbs that
// have no meaning for the type render as a Go %!verb error instead of falling
// back to reflection over the fields.
func Format(f fmt.State, verb rune, name string) {
	FormatWith(f, verb, name, String(false, name), GoString(false, name))
}

// FormatWith is Format for a type that prints more than a fixed marker: str is
// the %v, %+v and %s form and goStr the %#v form.
func FormatWith(f fmt.State, verb rune, name, str, goStr string) {
	switch verb {
	case 'v':
		if f.Flag('#') {
			_, _ = io.WriteString(f, goStr)
			return
		}
		_, _ = io.WriteString(f, str)
	case 's':
		_, _ = io.WriteString(f, str)
	case 'q':
		_, _ = fmt.Fprintf(f, "%q", str)
	default:
		_, _ = fmt.Fprintf(f, "%%!%c(%s)", verb, name)
	}
}
