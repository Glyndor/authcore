package domain

import (
	"strings"
	"testing"
)

func TestOf(t *testing.T) {
	cases := []struct{ address, want string }{
		{"user@example.com", "example.com"},
		{"notanemail", ""},
		{"", ""},
		{"user@", ""},
		{"a@b@example.com", "example.com"}, // the last '@' wins
	}
	for _, c := range cases {
		if got := Of(c.address); got != c.want {
			t.Errorf("Of(%q) = %q, want %q", c.address, got, c.want)
		}
	}
}

func TestPlausible(t *testing.T) {
	label63 := strings.Repeat("a", 63)
	cases := []struct {
		name   string
		domain string
		want   bool
	}{
		{"ordinary", "example.com", true},
		{"empty", "", false},
		{"empty label", "a..b", false},
		{"leading dot", ".example.com", false},
		{"trailing dot", "example.com.", false},
		{"63-byte label", label63 + ".example", true},
		{"64-byte label", strings.Repeat("a", 64) + ".example", false},
		{"253 bytes", strings.Repeat(label63+".", 3) + strings.Repeat("a", 61), true},
		{"254 bytes", strings.Repeat(label63+".", 3) + strings.Repeat("a", 62), false},
	}
	for _, c := range cases {
		if got := Plausible(c.domain); got != c.want {
			t.Errorf("%s: Plausible(%d bytes) = %v, want %v", c.name, len(c.domain), got, c.want)
		}
	}
}
