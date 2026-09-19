package password

import (
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/Glyndor/authcore"
	"golang.org/x/text/unicode/norm"
)

// FuzzValidatePolicy ensures the policy check never panics on arbitrary input,
// and that nothing it accepts holds invalid UTF-8 or a character that is not
// printable. Hash itself is too slow to fuzz (Argon2id is intentionally
// expensive).
func FuzzValidatePolicy(f *testing.F) {
	auth, err := authcore.New(authcore.Config{EnableLogs: false, KeysDir: f.TempDir()})
	if err != nil {
		f.Fatal(err)
	}
	mod, err := New(auth)
	if err != nil {
		f.Fatal(err)
	}

	seeds := []string{
		"", "short", "alllowercase1!",
		"ALLUPPERCASE1!", "NoDigits!", "NoSpecial1A",
		"ValidPass123!", strings.Repeat("a", 65) + "A1!",
		strings.Repeat("\x00", 12) + "A1!", "héllo Wörld 1!",
		"Abcdefghijk1\x00", "Abcdefghijk1!\u200d", "Abcdefghijk1!\xff",
		"Abcdefghijk1!\ufffd", "Abcdefghijk1漢", "Abcdefghijk 1",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, in string) {
		if err := mod.ValidatePolicy(in); err != nil {
			return
		}
		// ValidatePolicy judges the NFC form, so the oracle reads the same one.
		accepted := norm.NFC.String(in)
		if !utf8.ValidString(accepted) {
			t.Fatalf("ValidatePolicy accepted invalid UTF-8: %+q", in)
		}
		for _, r := range accepted {
			if r == utf8.RuneError || !unicode.IsPrint(r) {
				t.Fatalf("ValidatePolicy accepted %+q, which holds the non-printable %U", in, r)
			}
		}
	})
}

// FuzzParsePHC ensures the PHC parser never panics on arbitrary stored hashes.
func FuzzParsePHC(f *testing.F) {
	seeds := []string{
		"", "$", "$$$$$$",
		"$argon2id$v=19$m=65536,t=3,p=2$AAAA$AAAA",
		"$argon2i$v=19$m=65536,t=3,p=2$AAAA$AAAA",
		"$argon2id$v=99$m=65536,t=3,p=2$AAAA$AAAA",
		"$argon2id$v=19$m=x,t=y,p=z$AAAA$AAAA",
		"$argon2id$v=19$m=65536,t=3,p=2$!!!!$AAAA",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, in string) {
		_, _, _, _ = parsePHC(in)
	})
}
