package password_test

import (
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/password"
)

// FuzzValidatePolicyNormalisation checks the policy against arbitrary text. It
// must never panic; the verdict is the same for every canonical spelling of a
// password (composed and decomposed forms agree); and a password it accepts is
// valid UTF-8, within the length limits counted in characters after
// normalisation, and free of control characters.
func FuzzValidatePolicyNormalisation(f *testing.F) {
	auth, err := authcore.New(authcore.Config{EnableLogs: false, KeysDir: f.TempDir()})
	if err != nil {
		f.Fatal(err)
	}
	mod, err := password.New(auth, password.Config{Memory: 8 * 1024, Iterations: 1, Parallelism: 1})
	if err != nil {
		f.Fatal(err)
	}
	for _, s := range []string{
		"", "Correct-Horse-9", "Caf\u00e9-Mu\u00f1oz-9", "Cafe\u0301-Mu\u00f1oz-9", "Aa1!" + strings.Repeat("e\u0301", 40),
		"Aa1!\x00aaaaaaaa", "Aa1!\u200baaaaaaa", "\xff\xfe", strings.Repeat("A", 2000), "\u01c5\u01c5\u01c5\u01c5-9a\u01c5\u01c5\u01c5\u01c5",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		err := mod.ValidatePolicy(in)
		if utf8.ValidString(in) {
			for _, form := range []string{norm.NFC.String(in), norm.NFD.String(in)} {
				if other := mod.ValidatePolicy(form); (other == nil) != (err == nil) {
					t.Fatalf("spellings %q and %q of one password disagree: %v and %v", in, form, err, other)
				}
			}
		}
		if err != nil {
			return
		}
		if !utf8.ValidString(in) {
			t.Fatalf("accepted invalid UTF-8 %q", in)
		}
		n := utf8.RuneCountInString(norm.NFC.String(in))
		if n < 12 || n > 64 {
			t.Fatalf("accepted %q with %d characters", in, n)
		}
		for _, r := range in {
			if unicode.IsControl(r) {
				t.Fatalf("accepted %q holding the control character U+%04X", in, r)
			}
		}
	})
}
