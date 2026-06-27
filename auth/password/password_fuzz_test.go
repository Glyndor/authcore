package password

import (
	"strings"
	"testing"

	"github.com/Glyndor/authcore"
)

// FuzzValidatePolicy ensures the policy check never panics on arbitrary input.
// Hash itself is too slow to fuzz (Argon2id is intentionally expensive).
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
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, in string) {
		_ = mod.ValidatePolicy(in)
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
