package phc_test

import (
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/password"
	"github.com/Glyndor/authcore/auth/password/internal/phc"
)

func TestVerify_malformedHashReturnsErrInvalidHash(t *testing.T) {
	mod := newMod(t)

	_, err := mod.Verify("password", "not-a-phc-string")
	if !errors.Is(err, password.ErrInvalidHash) {
		t.Errorf("expected password.ErrInvalidHash, got %v", err)
	}
}

func TestVerify_rejectsLeadingGarbage(t *testing.T) {
	mod := newMod(t)

	const pw = "Correct-Horse-9!"
	clean, err := mod.Hash(pw)
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}

	// Acceptance pair: the clean hash must still verify, so this is a test of
	// the prefix check rather than a regression that turned the whole parser
	// against every hash.
	ok, err := mod.Verify(pw, clean)
	if err != nil || !ok {
		t.Fatalf("clean hash must still verify: ok=%v err=%v", ok, err)
	}

	ok, err = mod.Verify(pw, "junk"+clean)
	if ok {
		t.Errorf("Verify with junk-prefixed PHC must not succeed, got ok=true")
	}
	if !errors.Is(err, password.ErrInvalidHash) {
		t.Errorf("Verify with junk-prefixed PHC: expected password.ErrInvalidHash, got %v", err)
	}
}

// itoa formats n in base 10. strconv.Itoa would do, but keeping the helper
// local makes the test self-contained.
func itoa(n int) string { return strconv.Itoa(n) }

// A stored hash whose parameter label is shorter than "label=" is refused,
// not sliced out of range. Without the prefix check in labeledValue, Verify
// panicked on "$argon2id$v$...", and the canonical-form check runs too late
// to help.
func TestVerify_refusesAHashWithABareLabel(t *testing.T) {
	mod := newMod(t)
	valid := phcFixture(t, "argon2id", 19, phc.MinMemory, 3, 1)
	for name, hash := range map[string]string{
		"bare v": strings.Replace(valid, "v=19", "v", 1),
		"bare m": strings.Replace(valid, "m="+itoa(phc.MinMemory), "m", 1),
		"bare t": strings.Replace(valid, "t=3", "t", 1),
		"bare p": strings.Replace(valid, "p=1", "p", 1),
		"empty":  strings.Replace(valid, "v=19", "", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if hash == valid {
				t.Fatal("fixture unchanged")
			}
			ok, err := mod.Verify("Correct-Horse-Battery-9", hash)
			if ok || !errors.Is(err, password.ErrInvalidHash) {
				t.Fatalf("Verify = %v, %v; want false, password.ErrInvalidHash", ok, err)
			}
		})
	}
}
