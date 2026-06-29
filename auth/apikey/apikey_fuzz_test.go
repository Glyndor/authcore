package apikey_test

import (
	"strings"
	"testing"
)

// FuzzParseID drives ParseID with arbitrary input. ParseID runs on the raw key
// a client presents, so it must never panic — only return an id or ErrInvalidKey
// — and must never accept a key whose structure it cannot validate.
func FuzzParseID(f *testing.F) {
	m := newMod(f)

	key, _ := m.Generate()
	f.Add(key.Key)
	f.Add("")
	f.Add("ak_")
	f.Add("ak_" + strings.Repeat("0", 32) + "_secret")
	f.Add("not-even-close")
	f.Add("ak_zzzz_zzzz")

	f.Fuzz(func(t *testing.T, raw string) {
		id, err := m.ParseID(raw)
		if err != nil {
			return // rejected — fine
		}
		// A returned id must be the canonical 32-char hex and must round-trip
		// back out of the input.
		if len(id) != 32 {
			t.Fatalf("ParseID accepted %q and returned a non-canonical id %q", raw, id)
		}
		if !strings.Contains(raw, id) {
			t.Fatalf("ParseID(%q) returned id %q that is not in the input", raw, id)
		}
	})
}
