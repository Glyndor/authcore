package safetext_test

import (
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/Glyndor/authcore/auth/oauth/internal/safetext"
)

// FuzzClip checks what a log line depends on, for any input: valid UTF-8,
// nothing unprintable, and a size bounded by the limit.
func FuzzClip(f *testing.F) {
	f.Add("invalid_grant", 64)
	f.Add("a\nb\rc\x1b[31m", 8)
	f.Add("\xff\xfe\xc3", 2)
	f.Add(strings.Repeat("é", 400), 512)
	f.Add("a b\u0085c", 3)

	f.Fuzz(func(t *testing.T, s string, max int) {
		if max < 0 || max > 1<<12 {
			t.Skip()
		}
		got := safetext.Clip(s, max)
		if !utf8.ValidString(got) {
			t.Fatalf("Clip(%q, %d) = %q: not valid UTF-8", s, max, got)
		}
		if len(got) > max+len("…") {
			t.Fatalf("Clip(%q, %d) is %d bytes", s, max, len(got))
		}
		for _, r := range got {
			if !unicode.IsPrint(r) {
				t.Fatalf("Clip(%q, %d) = %q keeps %U", s, max, got, r)
			}
		}
	})
}
