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
		again, err := mod.ValidateAndNormalize(got)
		if err != nil {
			t.Fatalf("canonical form rejected: %q err=%v", got, err)
		}
		if again != got {
			t.Fatalf("not idempotent: %q → %q", got, again)
		}
	})
}
