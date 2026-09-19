package password

import (
	"errors"
	"strings"
	"testing"
)

// validBase satisfies the default policy on its own: 13 characters, upper,
// lower, digit and a real symbol. A case that appends one character to it is
// valid in every respect except that character.
const validBase = "Abcdefghijk1!"

// noSymbolBase is the password from #347: 12 characters, upper, lower and
// digit, and nothing that counts as special.
const noSymbolBase = "Abcdefghijk1"

// legacyNULHash is the hash of noSymbolBase + "\x00", produced by Hash at
// 6396536, before the printable rule existed. It stands for a row a consumer
// already has in their database.
const legacyNULHash = "$argon2id$v=19$m=8192,t=1,p=1$5g7AVEqEb1DKIDz4W2qrtQ$6H4W+iVKrUAOrslx9tRcAAf19BKz3WUFA0bE7MI4xwU"

// ---- the printable rule -----------------------------------------------------

func TestValidatePolicy_rejectsNonPrintableCharacters(t *testing.T) {
	mod := fastMod(t, Config{})

	if err := mod.ValidatePolicy(validBase); err != nil {
		t.Fatalf("test setup: ValidatePolicy(%q) = %v, the base must be valid on its own", validBase, err)
	}

	cases := []struct {
		name string
		char string
	}{
		{"NUL", "\x00"},
		{"newline", "\n"},
		{"tab", "\t"},
		{"DEL", "\x7f"},
		{"C1 control", "\u0085"},
		{"zero-width joiner", "‍"},
		{"no-break space", " "},
		{"unassigned code point", "͸"},
		{"noncharacter", "￿"},
		{"private use", ""},
		{"invalid UTF-8 byte", "\xff"},
		{"replacement character", "�"},
	}

	for _, tc := range cases {
		for _, pos := range []struct {
			where string
			pwd   string
		}{
			{"trailing", validBase + tc.char},
			{"leading", tc.char + validBase},
			{"inside", validBase[:5] + tc.char + validBase[5:]},
		} {
			t.Run(tc.name+"/"+pos.where, func(t *testing.T) {
				err := mod.ValidatePolicy(pos.pwd)
				if !errors.Is(err, ErrNonPrintableCharacter) {
					t.Fatalf("ValidatePolicy(%+q) = %v, want ErrNonPrintableCharacter", pos.pwd, err)
				}
				if !errors.Is(err, ErrWeakPassword) {
					t.Errorf("ValidatePolicy(%+q) = %v, must also match ErrWeakPassword", pos.pwd, err)
				}
			})
		}
	}
}

func TestValidatePolicy_issue347(t *testing.T) {
	mod := fastMod(t, Config{})

	// The pair from the issue. Before the fix the first was the accepted one.
	err := mod.ValidatePolicy(noSymbolBase + "\x00")
	if !errors.Is(err, ErrNonPrintableCharacter) {
		t.Errorf("ValidatePolicy(%+q) = %v, want ErrNonPrintableCharacter", noSymbolBase+"\x00", err)
	}
	if err := mod.ValidatePolicy(noSymbolBase + "!"); err != nil {
		t.Errorf("ValidatePolicy(%q) = %v, the same password with a real symbol must pass", noSymbolBase+"!", err)
	}
}

func TestValidatePolicy_nonPrintableReasonIsClientSafe(t *testing.T) {
	mod := fastMod(t, Config{})

	err := mod.ValidatePolicy(validBase + "\x00")
	if err == nil {
		t.Fatal("ValidatePolicy accepted a NUL")
	}
	reason := errors.Unwrap(err)
	if reason != ErrNonPrintableCharacter {
		t.Fatalf("errors.Unwrap(err) = %v, want the ErrNonPrintableCharacter sentinel itself", reason)
	}
	if got, want := reason.Error(), "must contain only printable characters"; got != want {
		t.Errorf("reason = %q, want %q", got, want)
	}
	if strings.ContainsRune(err.Error(), 0) {
		t.Error("the error text must not echo the offending character")
	}
}

// The printable rule is not a product rule. Turning every class off must not
// turn it off with them.
func TestValidatePolicy_nonPrintableRejectedWithEveryClassOff(t *testing.T) {
	mod := fastMod(t, Config{
		RequireUpper:  Bool(false),
		RequireLower:  Bool(false),
		RequireDigit:  Bool(false),
		RequireSymbol: Bool(false),
	})

	const plain = "abcdefghijkl"
	if err := mod.ValidatePolicy(plain); err != nil {
		t.Fatalf("ValidatePolicy(%q) = %v, want nil with every class off", plain, err)
	}
	if err := mod.ValidatePolicy(plain + "\x00"); !errors.Is(err, ErrNonPrintableCharacter) {
		t.Errorf("ValidatePolicy(%+q) = %v, want ErrNonPrintableCharacter with every class off", plain+"\x00", err)
	}
}

func TestHash_rejectsNonPrintableAndReturnsNoHash(t *testing.T) {
	mod := fastMod(t, Config{})

	hash, err := mod.Hash(noSymbolBase + "\x00")
	if !errors.Is(err, ErrNonPrintableCharacter) {
		t.Errorf("Hash(%+q) error = %v, want ErrNonPrintableCharacter", noSymbolBase+"\x00", err)
	}
	if hash != "" {
		t.Errorf("Hash(%+q) returned %q alongside the rejection, want no hash", noSymbolBase+"\x00", hash)
	}

	hash, err = mod.Hash(noSymbolBase + "!")
	if err != nil {
		t.Fatalf("Hash(%q) error = %v, want nil", noSymbolBase+"!", err)
	}
	if ok, err := mod.Verify(noSymbolBase+"!", hash); err != nil || !ok {
		t.Errorf("Verify of the accepted password = %v, %v, want true, nil", ok, err)
	}
}

// ---- the special class ------------------------------------------------------

func TestValidatePolicy_specialClassMembers(t *testing.T) {
	mod := fastMod(t, Config{})

	cases := []struct {
		name string
		char string
	}{
		{"ASCII punctuation", "!"},
		{"ASCII space", " "},
		{"ASCII math symbol", "+"},
		{"ASCII modifier symbol", "^"},
		{"non-ASCII punctuation", "¿"},
		{"currency symbol", "€"},
		{"other symbol", "©"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pwd := noSymbolBase + tc.char
			if err := mod.ValidatePolicy(pwd); err != nil {
				t.Errorf("ValidatePolicy(%q) = %v, %q must satisfy the special rule", pwd, err, tc.char)
			}
		})
	}
}

func TestValidatePolicy_printableOutsideTheClassesIsNotSpecial(t *testing.T) {
	strict := fastMod(t, Config{})
	noSymbolRule := fastMod(t, Config{RequireSymbol: Bool(false)})

	cases := []struct {
		name string
		char string
	}{
		{"caseless letter (CJK)", "漢"},
		{"caseless letter (Hebrew)", "א"},
		{"titlecase letter", "ǅ"},
		{"modifier letter", "ʰ"},
		{"combining mark", "́"},
		{"non-decimal number", "½"},
		{"letter number", "Ⅷ"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pwd := noSymbolBase + tc.char

			// It does not count as special.
			err := strict.ValidatePolicy(pwd)
			if !errors.Is(err, ErrWeakPassword) {
				t.Fatalf("ValidatePolicy(%q) = %v, want ErrWeakPassword: %q must not satisfy the special rule", pwd, err, tc.char)
			}
			if !strings.Contains(err.Error(), "at least one special character") {
				t.Errorf("ValidatePolicy(%q) = %v, want the special character reason", pwd, err)
			}
			if errors.Is(err, ErrNonPrintableCharacter) {
				t.Errorf("ValidatePolicy(%q) = %v, a printable character must not be reported as non-printable", pwd, err)
			}

			// It is still allowed: fine once a real symbol is present, and fine
			// when the caller does not ask for a symbol at all.
			if err := strict.ValidatePolicy(pwd + "!"); err != nil {
				t.Errorf("ValidatePolicy(%q) = %v, want nil", pwd+"!", err)
			}
			if err := noSymbolRule.ValidatePolicy(pwd); err != nil {
				t.Errorf("ValidatePolicy(%q) with RequireSymbol off = %v, want nil", pwd, err)
			}
		})
	}
}

// ---- Verify applies no policy -----------------------------------------------

// A user whose stored password holds a character Hash now refuses must still
// be able to sign in. Verify compares, and nothing else.
func TestVerify_acceptsLegacyHashOfNonPrintablePassword(t *testing.T) {
	mod := fastMod(t, Config{})

	if _, err := mod.Hash(noSymbolBase + "\x00"); !errors.Is(err, ErrNonPrintableCharacter) {
		t.Fatalf("test setup: Hash must refuse this password today, got %v", err)
	}

	ok, err := mod.Verify(noSymbolBase+"\x00", legacyNULHash)
	if err != nil {
		t.Fatalf("Verify(legacy hash) error = %v, want nil", err)
	}
	if !ok {
		t.Error("Verify(legacy hash) = false, the password it was made from must still verify")
	}

	ok, err = mod.Verify(noSymbolBase, legacyNULHash)
	if err != nil {
		t.Fatalf("Verify(legacy hash, password without the NUL) error = %v, want nil", err)
	}
	if ok {
		t.Error("Verify(legacy hash) = true without the NUL, the NUL is part of the password")
	}
}
