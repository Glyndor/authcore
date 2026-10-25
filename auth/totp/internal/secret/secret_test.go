package secret

import (
	"encoding/base32"
	"errors"
	"strings"
	"testing"
)

func TestNew_decodesToLenBytes(t *testing.T) {
	a, err := New()
	if err != nil {
		t.Fatal(err)
	}
	b, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatalf("two secrets are equal: %q", a)
	}
	key, err := Decode(a)
	if err != nil || len(key) != Len {
		t.Fatalf("Decode(New()) = %d bytes, %v; want %d bytes", len(key), err, Len)
	}
}

// Only the exact spelling New hands out is accepted: right length, no padding
// differences, no line breaks, nothing the decoder would skip.
func TestDecode_acceptsOnlyTheMintedSpelling(t *testing.T) {
	good := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(make([]byte, Len))
	if _, err := Decode(good); err != nil {
		t.Fatalf("Decode(%q) = %v, want accepted", good, err)
	}
	for name, in := range map[string]string{
		"empty":              "",
		"five bytes":         "MZXW6YTB",
		"too long":           strings.Repeat("A", 41),
		"not base32":         strings.Repeat("1", 32),
		"lowercase":          strings.ToLower(good[:31]) + "a",
		"line break":         good[:10] + "\n" + good[10:],
		"carriage return":    good[:10] + "\r" + good[10:],
		"one group short":    good[:24],
		"one group long":     good + "AAAAAAAA",
		"padding at the end": good + "=",
	} {
		if _, err := Decode(in); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: Decode(%q) = %v, want ErrInvalid", name, in, err)
		}
	}
}
