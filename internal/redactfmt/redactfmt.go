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
	switch verb {
	case 'v':
		if f.Flag('#') {
			_, _ = io.WriteString(f, GoString(false, name))
			return
		}
		_, _ = io.WriteString(f, String(false, name))
	case 's':
		_, _ = io.WriteString(f, String(false, name))
	case 'q':
		_, _ = fmt.Fprintf(f, "%q", String(false, name))
	default:
		_, _ = fmt.Fprintf(f, "%%!%c(%s)", verb, name)
	}
}
