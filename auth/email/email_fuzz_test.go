package email

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
	f.Cleanup(mod.Close)

	seeds := []string{
		"", " ", "@", "a@b", "a@b.c", "user@example.com",
		"USER@EXAMPLE.COM", "  user@example.com  ",
		"a..b@example.com", "a@.example.com", "a@example..com",
		"a@example.", strings.Repeat("a", 65) + "@example.com",
		strings.Repeat("a", 250) + "@example.com",
		"\x00@example.com", "user@\x00.com", "user@example.com\n",
		// IDN domains: normalization converts these to ASCII punycode.
		"user@münchen.de", "USER@例え.JP", "0@Ȟ.0",
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
		// The normalized form must be canonical — trimmed and lowercase.
		// It is not necessarily strings.ToLower(strings.TrimSpace(in)):
		// normalization also converts IDN domains to ASCII punycode, so
		// "0@Ȟ.0" canonicalises to "0@xn--4la.0", not "0@ȟ.0".
		if got != strings.TrimSpace(got) {
			t.Fatalf("normalized form has surrounding whitespace: %q", got)
		}
		if got != strings.ToLower(got) {
			t.Fatalf("normalized form is not lowercase: %q", got)
		}
		again, err := mod.ValidateAndNormalize(got)
		if err != nil {
			t.Fatalf("normalized form rejected: %q err=%v", got, err)
		}
		if again != got {
			t.Fatalf("normalize not idempotent: %q → %q", got, again)
		}
	})
}
