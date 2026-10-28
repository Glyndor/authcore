package field

import (
	"fmt"
	"log/slog"

	"github.com/Glyndor/authcore/internal/redactfmt"
)

const redactedName = "field.Field"

var (
	_ fmt.Formatter  = Field{}
	_ fmt.Formatter  = (*Field)(nil)
	_ fmt.Stringer   = (*Field)(nil)
	_ fmt.GoStringer = (*Field)(nil)
	_ slog.LogValuer = (*Field)(nil)
)

// Format redacts the module held by value or pointer for every verb.
func (f Field) Format(s fmt.State, verb rune) { redactfmt.Format(s, verb, redactedName) }

// String returns a fixed description without key material, including for nil.
func (f *Field) String() string { return redactfmt.String(f == nil, redactedName) }

// GoString returns the redacted Go representation, including for nil.
func (f *Field) GoString() string { return redactfmt.GoString(f == nil, redactedName) }

// LogValue redacts the module for slog, including for nil.
func (f *Field) LogValue() slog.Value { return redactfmt.LogValue(f == nil, redactedName) }
