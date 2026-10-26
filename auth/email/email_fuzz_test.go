package email

import (
	"strings"
	"testing"
	"unicode"

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

// FuzzAcceptedAddressIsSafe states what an accepted address is, for any input:
// valid UTF-8, within the length limits, exactly one at sign, an ASCII domain
// in lower case, and no control, space or format character anywhere. The
// sibling target checks that normalising twice changes nothing; this one
// checks the content of what comes out.
func FuzzAcceptedAddressIsSafe(f *testing.F) {
	auth, err := authcore.New(authcore.Config{EnableLogs: false, KeysDir: f.TempDir()})
	if err != nil {
		f.Fatal(err)
	}
	mod, err := New(auth)
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(mod.Close)
	for _, s := range []string{
		"a@b.c", "A@B.C", "al\u200bice@example.com", "a@\u00ad.com",
		"\u212aevin@example.com", "a@b\u3002com", "\u0130@example.com", "a@\u0430pple.com",
		"a@b.com\u2028", "al\xffice@example.com", "a@xn--a.com", "a b@c.d", "\"a\"@b.cc", "a@[1.2.3.4]",
		strings.Repeat("a", 64) + "@" + strings.Repeat("b", 63) + ".com",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		got, err := mod.ValidateAndNormalize(in)
		if err != nil {
			return
		}
		if len(got) == 0 || len(got) > 254 {
			t.Fatalf("accepted %q with length %d", got, len(got))
		}
		if strings.Count(got, "@") != 1 {
			t.Fatalf("accepted %q without exactly one at sign", got)
		}
		at := strings.IndexByte(got, '@')
		if at == 0 || at > 64 {
			t.Fatalf("accepted %q with a local part of %d bytes", got, at)
		}
		for _, r := range got {
			if unicode.IsControl(r) || unicode.IsSpace(r) || unicode.Is(unicode.Cf, r) {
				t.Fatalf("accepted %q holding U+%04X", got, r)
			}
		}
		for _, r := range got[at+1:] {
			if r > unicode.MaxASCII || unicode.IsUpper(r) {
				t.Fatalf("accepted %q whose domain is not lower case ASCII", got)
			}
		}
	})
}
