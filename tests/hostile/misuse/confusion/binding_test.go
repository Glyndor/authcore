// Package confusion hands the right values to the wrong parameter: subject and
// purpose swapped, a token where a hash belongs, an access token where a
// refresh token is expected, the empty string, and text in forms that look the
// same and compare differently. Each call must come back as a refusal.
package confusion

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/apikey"
	"github.com/Glyndor/authcore/auth/credential"
	"github.com/Glyndor/authcore/auth/field"
	"github.com/Glyndor/authcore/tests/hostile/misuse/hostiletest"
)

// A credential is bound to its purpose and its subject. Passing them in the
// other order, or the hash where the token goes, never verifies.
func TestMisuse_Confusion_credentialBindingSurvivesSwappedArguments(t *testing.T) {
	e := hostiletest.NewEnv(t)
	cr, _ := credential.New(e.AC)
	iss, err := cr.Issue("reset", hostiletest.Subject)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := cr.Verify("reset", hostiletest.Subject, iss.Token, iss.Hash, now); err != nil {
		t.Fatalf("control: the issued credential does not verify: %v", err)
	}
	cases := map[string]error{
		"purpose and subject swapped": cr.Verify(hostiletest.Subject, "reset", iss.Token, iss.Hash, now),
		"token and hash swapped":      cr.Verify("reset", hostiletest.Subject, iss.Hash, iss.Token, now),
		"another purpose":             cr.Verify("verify", hostiletest.Subject, iss.Token, iss.Hash, now),
		"another subject":             cr.Verify("reset", hostiletest.Other, iss.Token, iss.Hash, now),
		"empty purpose":               cr.Verify("", hostiletest.Subject, iss.Token, iss.Hash, now),
		"empty subject":               cr.Verify("reset", "", iss.Token, iss.Hash, now),
		"empty token":                 cr.Verify("reset", hostiletest.Subject, "", iss.Hash, now),
		"issued in the future":        cr.Verify("reset", hostiletest.Subject, iss.Token, iss.Hash, now.Add(time.Hour)),
		"hash of the token elsewhere": cr.Verify("reset", hostiletest.Subject, iss.Token, mustHash(t, e, iss.Token), now),
	}
	for name, err := range cases {
		want := credential.ErrInvalidCredential
		if name == "issued in the future" {
			want = credential.ErrExpired
		}
		if !errors.Is(err, want) {
			t.Errorf("%s: %v; want %v", name, err, want)
		}
	}
}

func mustHash(t *testing.T, e *hostiletest.Env, s string) string {
	t.Helper()
	ak, err := apikey.New(e.AC)
	if err != nil {
		t.Fatal(err)
	}
	h, err := ak.Hash(s)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// Purpose and subject are length-framed. Moving a character across the
// boundary gives a different binding, so "ab"+"c" is not "a"+"bc".
func TestMisuse_Confusion_credentialFramingHasNoAmbiguousSplit(t *testing.T) {
	e := hostiletest.NewEnv(t)
	cr, _ := credential.New(e.AC)
	iss, err := cr.Issue("ab", "c")
	if err != nil {
		t.Fatal(err)
	}
	for _, split := range [][2]string{{"a", "bc"}, {"abc", ""}, {"", "abc"}, {"ab\x00", "c"}, {"ab:", "c"}} {
		if err := cr.Verify(split[0], split[1], iss.Token, iss.Hash, time.Now()); !errors.Is(err, credential.ErrInvalidCredential) {
			t.Errorf("split %q: %v; want ErrInvalidCredential", split, err)
		}
	}
}

// Empty purpose and subject are refused when issuing, with the sentinel the
// package documents for each.
func TestMisuse_Confusion_credentialIssueRefusesEmptyBindings(t *testing.T) {
	e := hostiletest.NewEnv(t)
	cr, _ := credential.New(e.AC)
	if _, err := cr.Issue("", hostiletest.Subject); !errors.Is(err, credential.ErrEmptyPurpose) {
		t.Errorf("empty purpose: %v", err)
	}
	if _, err := cr.Issue("reset", ""); !errors.Is(err, credential.ErrEmptySubject) {
		t.Errorf("empty subject: %v", err)
	}
}

// Text that renders alike and compares differently is bound as written. A
// credential for one spelling does not verify for the other, and none panics.
func TestMisuse_Confusion_credentialUnicodeIsBoundAsWritten(t *testing.T) {
	e := hostiletest.NewEnv(t)
	cr, _ := credential.New(e.AC)
	nfc, nfd := "café", "café"
	hostiletest.NoPanic(t, "unicode credential", func() {
		iss, err := cr.Issue("reset", nfc)
		if err != nil {
			t.Fatal(err)
		}
		if err := cr.Verify("reset", nfc, iss.Token, iss.Hash, time.Now()); err != nil {
			t.Errorf("control: %v", err)
		}
		if err := cr.Verify("reset", nfd, iss.Token, iss.Hash, time.Now()); !errors.Is(err, credential.ErrInvalidCredential) {
			t.Errorf("the decomposed spelling against a credential issued for the composed one: %v; want ErrInvalidCredential", err)
		}
		for _, odd := range []string{"\u202eevil", "a\x00b", strings.Repeat("é", 4096), "👩‍💻"} {
			if _, err := cr.Issue(odd, odd); err != nil {
				t.Errorf("%q: %v", odd, err)
			}
		}
	})
}

// A ciphertext belongs to its context, and the blind index of one context
// reveals nothing usable in another. Passing the wrong thing to Decrypt fails.
func TestMisuse_Confusion_fieldContextsAndWrongInputs(t *testing.T) {
	e := hostiletest.NewEnv(t)
	mail, _ := field.New(e.AC, field.Config{Context: "users.email"})
	phone, _ := field.New(e.AC, field.Config{Context: "users.phone"})

	ct, err := mail.Encrypt("ana@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := phone.Decrypt(ct); !errors.Is(err, field.ErrDecrypt) {
		t.Errorf("a ciphertext decrypts under another column's context: %v", err)
	}
	bi, err := mail.BlindIndex("ana@example.com")
	if err != nil {
		t.Fatal(err)
	}
	other, _ := phone.BlindIndex("ana@example.com")
	if bi == other {
		t.Error("two contexts produce the same blind index for one value")
	}
	for name, in := range map[string]string{"the blind index": bi, "the plaintext": "ana@example.com", "empty": ""} {
		if _, err := mail.Decrypt(in); !errors.Is(err, field.ErrDecrypt) {
			t.Errorf("Decrypt(%s): %v", name, err)
		}
	}
}

// Empty and unusual text round-trips: it is data, not a sentinel.
func TestMisuse_Confusion_fieldRoundTripsAwkwardText(t *testing.T) {
	e := hostiletest.NewEnv(t)
	f, _ := field.New(e.AC, field.Config{Context: "notes"})
	for _, in := range []string{"", " ", "\x00", "\u202e", "café", "👩‍💻", strings.Repeat("é", 10000)} {
		ct, err := f.Encrypt(in)
		if err != nil {
			t.Errorf("Encrypt(%.12q): %v", in, err)
			continue
		}
		if got, err := f.Decrypt(ct); err != nil || got != in {
			t.Errorf("round trip of %.12q gave %.12q, %v", in, got, err)
		}
	}
	a, _ := f.BlindIndex("café")
	b, _ := f.BlindIndex("café")
	if a == b {
		t.Error("BlindIndex normalised its input; the contract says the caller does that")
	}
}
