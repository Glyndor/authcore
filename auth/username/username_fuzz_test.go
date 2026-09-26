package username

import (
	"strings"
	"testing"

	"github.com/Glyndor/authcore"
)

func FuzzValidateAndNormalize(f *testing.F) {
	auth, err := authcore.New(authcore.Config{EnableLogs: false, KeysDir: f.TempDir()})
	if err != nil {
		f.Fatal(err)
	}
	mod, err := New(auth)
	if err != nil {
		f.Fatal(err)
	}

	seeds := []string{
		"", "a", "ab", "abc", "alice123", "ALICE",
		"_alice", "alice_", "-alice", "alice-",
		"al__ice", "al--ice", "al-_ice",
		"alice!", "alice ", " alice", "admin", "root",
		strings.Repeat("a", 33), strings.Repeat("a", 32),
		"\x00alice", "alice\n",
		// A disallowed byte between two allowed ones: the start and end
		// rules refuse "alice!" and "\x00alice" on their own, so these are
		// the seeds that reach isAllowed.
		"al!ce", "al.ce", "al ce", "ali\x00ce", "al\u00e9ce",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, in string) {
		got, err := mod.ValidateAndNormalize(in)
		if err != nil {
			if got != "" {
				t.Fatalf("error path returned non-empty result: %q", got)
			}
			return
		}
		if got != strings.ToLower(strings.TrimSpace(in)) {
			t.Fatalf("not canonical: in=%q got=%q", in, got)
		}
		// The character set is the homoglyph control: every accepted byte
		// is one of [a-z0-9_-], the length is within bounds, and the name
		// is not reserved. Until 2026-09-25 the target checked none of it,
		// so deleting isAllowed passed 390 thousand executions.
		if len(got) < mod.minLen || len(got) > mod.maxLen {
			t.Fatalf("accepted %q of length %d outside [%d, %d]", got, len(got), mod.minLen, mod.maxLen)
		}
		for i := 0; i < len(got); i++ {
			c := got[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
				t.Fatalf("accepted %q with byte %q outside [a-z0-9_-]", got, c)
			}
		}
		if _, reserved := mod.reserved[got]; reserved {
			t.Fatalf("accepted the reserved name %q", got)
		}
		again, err := mod.ValidateAndNormalize(got)
		if err != nil {
			t.Fatalf("canonical form rejected: %q err=%v", got, err)
		}
		if again != got {
			t.Fatalf("not idempotent: %q → %q", got, again)
		}
	})
}
