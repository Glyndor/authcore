package apikey_test

import (
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/apikey"
)

// wellFormed is the documented key shape for the default prefix, written
// independently of ParseID so the oracle does not compare the code with itself.
var wellFormed = regexp.MustCompile(`^ak_([0-9a-f]{32})_[0-9a-f]{64}$`)

// FuzzParseID drives ParseID with arbitrary input. ParseID runs on the raw key
// a client presents, so it must never panic, and it must accept exactly the
// documented shape: every well-formed key returns its id, and nothing else is
// accepted. The previous oracle only checked that a returned id appeared
// somewhere in the input, which a key with a malformed secret or a fourth field
// satisfied until #440.
func FuzzParseID(f *testing.F) {
	m := newMod(f)

	key, _ := m.Generate()
	f.Add(key.Key)
	f.Add(key.Key + "_extra")
	f.Add(strings.ToUpper(key.Key))
	f.Add("")
	f.Add("ak_")
	f.Add("ak_" + strings.Repeat("0", 32) + "_secret")
	f.Add("not-even-close")
	f.Add("ak_zzzz_zzzz")

	f.Fuzz(func(t *testing.T, raw string) {
		id, err := m.ParseID(raw)
		match := wellFormed.FindStringSubmatch(raw)
		switch {
		case match == nil && err == nil:
			t.Fatalf("ParseID accepted %q, which is not the documented shape (id %q)", raw, id)
		case match != nil && err != nil:
			t.Fatalf("ParseID refused the well-formed key %q: %v", raw, err)
		case match != nil && id != match[1]:
			t.Fatalf("ParseID(%q) = %q, want %q", raw, id, match[1])
		case err != nil && !errors.Is(err, apikey.ErrInvalidKey):
			t.Fatalf("ParseID(%q) refused with %v, want ErrInvalidKey", raw, err)
		}
	})
}
