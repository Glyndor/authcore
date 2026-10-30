package jsonstrict_test

import (
	"encoding/json"
	"strings"
)

// referenceDepth mirrors the number of open levels that keep a name table.
const referenceDepth = 64

// referenceAmbiguous is an independent model of UniqueMembers for a valid
// document. It walks the tokens encoding/json reads and keeps a fresh name set
// per object, comparing names exactly as the decoder returns them. Only the
// top-level object folds case, and only against the canonical names. Levels
// from referenceDepth down are not tracked.
func referenceAmbiguous(raw []byte, canonical []string) bool {
	return walkValue(json.NewDecoder(strings.NewReader(string(raw))), 0, canonical)
}

// walkValue consumes one value and reports whether it holds an ambiguity. It
// never stops early so the decoder always ends on a value boundary.
func walkValue(dec *json.Decoder, level int, canonical []string) bool {
	tok, err := dec.Token()
	if err != nil {
		return false
	}
	delim, isDelim := tok.(json.Delim)
	if !isDelim {
		return false
	}
	found := false
	if delim == '[' {
		for dec.More() {
			found = walkValue(dec, level+1, canonical) || found
		}
	} else {
		seen := map[string]bool{}
		for dec.More() {
			nameTok, _ := dec.Token()
			name, _ := nameTok.(string)
			if level < referenceDepth {
				found = referenceRepeats(seen, name, level, canonical) || found
			}
			found = walkValue(dec, level+1, canonical) || found
		}
	}
	_, _ = dec.Token()
	return found
}

// referenceRepeats records name and reports a repeat, or a case-only spelling
// of a canonical name in the top-level object.
func referenceRepeats(seen map[string]bool, name string, level int, canonical []string) bool {
	repeated := seen[name]
	seen[name] = true
	if level == 0 {
		for _, exact := range canonical {
			if name != exact && strings.EqualFold(name, exact) {
				repeated = true
			}
		}
	}
	return repeated
}

// nestedPair wraps a pair of equal members in levels single-member objects, so
// the pair sits at that nesting level.
func nestedPair(levels int) []byte {
	return []byte(strings.Repeat(`{"a":`, levels) + `{"x":1,"x":2}` + strings.Repeat(`}`, levels))
}
