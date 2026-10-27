// Package jsonstrict reads a JSON document the way a strict reader does: one
// reading per document, and no text repaired behind the caller's back.
//
// encoding/json keeps the last of two equal member names and matches a name
// to a struct field without regard to case, so one document can mean different
// things to two readers that apply different rules. It also replaces what it
// cannot decode: invalid UTF-8 bytes and unpaired surrogate escapes both
// become U+FFFD, so two different texts can arrive as one.
package jsonstrict

// Once counts how many times a document writes one member.
//
// A JSON reader matches a member name to a field without regard to case and
// writes that field again for every member that matches it, so a document
// that spells a member two ways writes the same field twice and the last
// value wins. A member written twice is ambiguous: which spelling was meant
// is not knowable, so the document that writes it is refused.
type Once struct {
	writes int
}

// UnmarshalJSON records the write and keeps no value: the member is read for
// its name, not for what it holds.
func (o *Once) UnmarshalJSON([]byte) error {
	o.writes++
	return nil
}

// Twice reports whether the document wrote this member more than once.
func (o Once) Twice() bool { return o.writes > 1 }
