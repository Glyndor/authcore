package password

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/Glyndor/authcore"
	"golang.org/x/crypto/argon2"
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

// FuzzParsePHC drives the PHC parser with arbitrary stored hashes. It must
// never panic, and anything it accepts must be the exact string Hash would
// write for the parameters, salt and key it returned. A non-canonical string
// that parses verifies the same password its canonical form does; that is how
// "junk" + hash (#437) and m=4294975488 read as m=8192 (#451) got through,
// and a no-panic oracle saw neither.
func FuzzParsePHC(f *testing.F) {
	seeds := []string{
		"", "$", "$$$$$$",
		"$argon2id$v=19$m=65536,t=3,p=2$AAAA$AAAA",
		"$argon2i$v=19$m=65536,t=3,p=2$AAAA$AAAA",
		"$argon2id$v=99$m=65536,t=3,p=2$AAAA$AAAA",
		"$argon2id$v=19$m=x,t=y,p=z$AAAA$AAAA",
		"$argon2id$v=19$m=65536,t=3,p=2$!!!!$AAAA",
	}
	// The seeds above all fail on salt or key length, so without one valid
	// hash the fuzzer rarely reaches the end of the parser and the oracle
	// below never runs. This one parses.
	seeds = append(seeds, fmt.Sprintf("$argon2id$v=%d$m=%d,t=3,p=2$%s$%s", argon2.Version, minMemory,
		base64.RawStdEncoding.EncodeToString([]byte(strings.Repeat("s", saltLen))),
		base64.RawStdEncoding.EncodeToString([]byte(strings.Repeat("k", keyLen)))))
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, in string) {
		cfg, salt, key, err := parsePHC(in)
		if err != nil {
			return
		}
		canonical := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
			argon2.Version, cfg.Memory, cfg.Iterations, cfg.Parallelism,
			base64.RawStdEncoding.EncodeToString(salt),
			base64.RawStdEncoding.EncodeToString(key))
		if in != canonical {
			t.Fatalf("parsePHC accepted a non-canonical hash:\n got  %q\n want %q", in, canonical)
		}
	})
}
