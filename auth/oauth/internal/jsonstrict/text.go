package jsonstrict

import "unicode/utf8"

// WellFormedText reports whether the JSON text in raw is free of what
// encoding/json repairs: every byte must be valid UTF-8, and every surrogate
// escape must be part of a pair.
//
// A document that fails is refused rather than read: the repair would make two
// different texts indistinguishable, and the text a provider sends is the text
// an identity is read from.
func WellFormedText(raw []byte) bool {
	if !utf8.Valid(raw) {
		return false
	}
	return surrogatesPaired(raw)
}

// surrogatesPaired reports whether every surrogate escape in raw stands in a
// pair. A high surrogate must be followed by its low one, and a low surrogate
// on its own is no pair either. Every other escape carries no code point.
func surrogatesPaired(raw []byte) bool {
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\\' {
			continue
		}
		i++
		if i >= len(raw) {
			return false
		}
		if raw[i] != 'u' {
			continue
		}
		if i+5 > len(raw) {
			return false
		}
		cp, ok := hex4(raw[i+1 : i+5])
		if !ok {
			return false
		}
		i += 4
		switch {
		case cp >= 0xD800 && cp <= 0xDBFF:
			if i+7 > len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
				return false
			}
			low, ok := hex4(raw[i+3 : i+7])
			if !ok || low < 0xDC00 || low > 0xDFFF {
				return false
			}
			i += 6
		case cp >= 0xDC00 && cp <= 0xDFFF:
			return false
		}
	}
	return true
}

// hex4 reads the four hex digits of a \u escape.
func hex4(b []byte) (rune, bool) {
	var r rune
	for _, c := range b {
		switch {
		case c >= '0' && c <= '9':
			r = r*16 + rune(c-'0')
		case c >= 'a' && c <= 'f':
			r = r*16 + rune(c-'a'+10)
		case c >= 'A' && c <= 'F':
			r = r*16 + rune(c-'A'+10)
		default:
			return 0, false
		}
	}
	return r, true
}
