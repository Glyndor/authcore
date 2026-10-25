// Package safetext makes text that came from a remote party safe to put in an error message.
package safetext

import (
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// DefaultMax is the length, in bytes, Quote keeps of a remote value.
const DefaultMax = 256

const ellipsis = "…"

// Clip returns s as text a log line can carry: bytes that are not valid
// UTF-8 and runes that do not print (newlines, carriage returns, escape and
// the other control characters among them) become '?', and the result is cut
// at a rune boundary to at most max bytes, with an ellipsis added when
// something was dropped. Remote text is attacker-controlled, so an error that
// quotes it must neither let it forge log lines nor let it set the size of the
// message.
func Clip(s string, max int) string {
	var b strings.Builder
	for _, r := range s {
		if r == utf8.RuneError || !unicode.IsPrint(r) {
			r = '?'
		}
		if b.Len()+utf8.RuneLen(r) > max {
			b.WriteString(ellipsis)
			return b.String()
		}
		b.WriteRune(r)
	}
	return b.String()
}

// Quote is Clip(s, DefaultMax) as a Go-quoted string, for the %q slots of an
// error message.
func Quote(s string) string {
	return strconv.Quote(Clip(s, DefaultMax))
}
