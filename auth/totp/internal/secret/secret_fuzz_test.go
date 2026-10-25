package secret

import (
	"strings"
	"testing"
)

// FuzzDecode feeds Decode arbitrary text. It must never panic, it accepts only
// the one canonical spelling of a twenty byte key (so decoding then encoding
// returns the input), and it never accepts anything longer than the cap.
func FuzzDecode(f *testing.F) {
	good, err := New()
	if err != nil {
		f.Fatal(err)
	}
	for _, s := range []string{
		"", "A", good, strings.ToLower(good), good + "=", good[:31], good + "A", " " + good,
		strings.Repeat("A", 32), strings.Repeat("A", 41), "0000000000000000000000000000000",
		good[:16] + " " + good[16:], strings.Repeat("A", 1<<12),
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		key, err := Decode(in)
		if err != nil {
			if key != nil {
				t.Fatalf("an error came with a key for %q", in)
			}
			return
		}
		if len(key) != Len {
			t.Fatalf("accepted %q as a %d byte key", in, len(key))
		}
		if len(in) > maxEncodedLen {
			t.Fatalf("accepted %d characters, over the cap", len(in))
		}
		if encoding.EncodeToString(key) != in {
			t.Fatalf("accepted %q, which is not the canonical spelling of its key", in)
		}
	})
}
