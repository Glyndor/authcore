// Package strictjson refuses a JSON object whose keys can be read in more than
// one way.
//
// encoding/json keeps the last of two equal keys and matches a key to a struct
// field without regard to case, so one document can mean different things to
// two readers that apply different rules. A JWT header or payload this module
// issues never has such a key; one that does was written by someone else.
package strictjson

import (
	"bytes"
	"encoding/json"
	"fmt"
	"unicode"

	"github.com/Glyndor/authcore/auth/jwt/internal/jwterr"
)

// Check reads the top-level members of the JSON object in raw and returns an
// error wrapping jwterr.ErrTokenMalformed when
//
//   - the same key appears twice (compared after unescaping),
//   - two keys differ only in capitalisation, or
//   - a key matches one of known when capitalisation is ignored but is not
//     spelt exactly like it ("EXP" where "exp" is the claim).
//
// A key that no known name matches is free to be spelt as the issuer likes, so
// custom claims keep working; only a clash between two keys of the same object
// is refused. Nested values are skipped, not inspected.
//
// Check accepts anything that is not a JSON object, or is not valid JSON: the
// token parser that runs next rejects those with its own error, and keeping
// that verdict here avoids a second one.
func Check(raw []byte, known ...string) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil
	}
	folded := map[string]string{}
	for dec.More() {
		t, err := dec.Token()
		key, ok := t.(string)
		if err != nil || !ok {
			return nil
		}
		var skip json.RawMessage
		if dec.Decode(&skip) != nil {
			return nil
		}
		f := fold(key)
		if other, clash := folded[f]; clash {
			if other == key {
				return fmt.Errorf("%w: key %q appears more than once", jwterr.ErrTokenMalformed, key)
			}
			return fmt.Errorf("%w: keys %q and %q differ only in capitalisation", jwterr.ErrTokenMalformed, other, key)
		}
		folded[f] = key
		for _, k := range known {
			if key != k && fold(key) == fold(k) {
				return fmt.Errorf("%w: key %q must be spelt %q", jwterr.ErrTokenMalformed, key, k)
			}
		}
	}
	return nil
}

// fold maps a string to a form that is equal for any two strings that
// encoding/json would match to one field: each rune becomes the smallest member
// of its Unicode simple-folding orbit.
func fold(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		low := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if f < low {
				low = f
			}
		}
		out = append(out, low)
	}
	return string(out)
}
