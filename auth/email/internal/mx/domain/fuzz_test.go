package domain_test

import (
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/email/internal/mx/domain"
)

// fuzzPlausible is the size limit DNS puts on a domain name, written as a
// scan of the bytes: at most 253 bytes in all, and every label between 1 and
// 63 bytes. The limit counts bytes, not characters, so a label of
// multi-byte characters holds fewer of them than it has bytes.
func fuzzPlausible(name string) bool {
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	label := 0
	for i := 0; i < len(name); i++ {
		if name[i] == '.' {
			if label == 0 || label > 63 {
				return false
			}
			label = 0
			continue
		}
		label++
	}
	return label >= 1 && label <= 63
}

// FuzzPlausible drives the DNS size limits of a domain with arbitrary text.
// The contract: a domain fits DNS when it is at most 253 bytes long and
// every label it is cut into holds between 1 and 63 bytes. An empty label is
// a domain that does not fit, and so is one whose last label is empty.
func FuzzPlausible(f *testing.F) {
	f.Add("example.com")
	f.Add("")
	f.Add("a..b")
	f.Add(".example.com")
	f.Add("example.com.")
	f.Add(strings.Repeat("a", 63) + ".example")
	f.Add(strings.Repeat("a", 64) + ".example")
	// 253 bytes in all, and one byte more.
	label63 := strings.Repeat("a", 63)
	f.Add(label63 + "." + label63 + "." + label63 + "." + strings.Repeat("a", 61))
	f.Add(label63 + "." + label63 + "." + label63 + "." + strings.Repeat("a", 62))
	f.Add("localhost")
	f.Add(strings.Repeat("é", 32))

	f.Fuzz(func(t *testing.T, name string) {
		got := domain.Plausible(name)
		want := fuzzPlausible(name)
		if got != want {
			t.Fatalf("Plausible(%q) = %v, want %v", name, got, want)
		}
	})
}
