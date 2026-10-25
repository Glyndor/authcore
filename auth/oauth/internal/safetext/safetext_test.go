package safetext

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestClip(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, in string
		max      int
		want     string
	}{
		{"plain", "invalid_grant", 64, "invalid_grant"},
		{"newline and carriage return", "a\nb\rc", 64, "a?b?c"},
		{"escape", "\x1b[31mred", 64, "?[31mred"},
		{"line separator", "a b", 64, "a?b"},
		{"invalid utf-8", "a\xffb\xc3", 64, "a?b?"},
		{"cut at the limit", "abcdef", 3, "abc…"},
		{"exactly the limit", "abc", 3, "abc"},
		{"never splits a rune", "ééé", 3, "é…"},
		{"empty", "", 8, ""},
	} {
		if got := Clip(tc.in, tc.max); got != tc.want {
			t.Errorf("%s: Clip(%q, %d) = %q, want %q", tc.name, tc.in, tc.max, got, tc.want)
		}
	}
}

func TestClip_alwaysValidAndBounded(t *testing.T) {
	t.Parallel()
	in := strings.Repeat("é\x00\xff", 1<<16)
	got := Clip(in, 100)
	if !utf8.ValidString(got) {
		t.Fatalf("not valid UTF-8: %q", got)
	}
	if len(got) > 100+len("…") {
		t.Fatalf("%d bytes", len(got))
	}
}

func TestQuote(t *testing.T) {
	t.Parallel()
	if got := Quote("a\nb"); got != `"a?b"` {
		t.Fatalf("got %s", got)
	}
	if got := Quote(strings.Repeat(`"`, 10000)); len(got) > 2*(DefaultMax+len("…"))+2 {
		t.Fatalf("%d bytes", len(got))
	}
}
