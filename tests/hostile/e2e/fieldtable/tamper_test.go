package fieldtable

import (
	"encoding/base64"
	"errors"
	"testing"

	"github.com/Glyndor/authcore/auth/field"
	"github.com/Glyndor/authcore/tests/hostile/e2e/hostiletest"
)

// An attacker with write access to the table puts one row's ciphertext next to
// another row's index. The module alone decrypts it (it binds the column, not
// the row), which is why the guide confirms the index after the decrypt: with
// that step, the swapped row is "not found" for both addresses.
func TestE2E_Field_aSwappedCiphertextIsCaughtByTheConfirmation(t *testing.T) {
	s := newService(t)
	_ = s.register("alice@example.com")
	_ = s.register("bob@example.com")
	rows := s.users.Rows()
	alice, bob := rows[0], rows[1]

	// The poisoned table: bob's index now points at alice's ciphertext.
	poisoned := hostiletest.NewUsers()
	if _, err := poisoned.Insert(alice.EmailCT, bob.EmailIdx); err != nil {
		t.Fatal(err)
	}
	plain, err := s.fld.Decrypt(alice.EmailCT)
	if err != nil || plain != "alice@example.com" {
		t.Fatalf("module alone on the swapped ciphertext = %q, %v, want alice's address (column-bound only)", plain, err)
	}
	s.users = poisoned
	if _, err := s.login("bob@example.com"); !errors.Is(err, errNotFound) {
		t.Errorf("login as bob against the swapped row = %v, want not found", err)
	}
	if _, err := s.login("alice@example.com"); !errors.Is(err, errNotFound) {
		t.Errorf("login as alice, whose index is gone = %v, want not found", err)
	}
}

// Any change to the ciphertext is a decryption failure, never another value:
// every single-byte change, every truncation, an extension, and base64 that
// decodes to something else.
func TestE2E_Field_tamperedCiphertextNeverDecryptsToAValue(t *testing.T) {
	s := newService(t)
	ct, err := s.fld.Encrypt("alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawStdEncoding.DecodeString(ct)
	if err != nil {
		t.Fatal(err)
	}
	check := func(name string, b []byte) {
		t.Helper()
		got, err := s.fld.Decrypt(base64.RawStdEncoding.EncodeToString(b))
		if !errors.Is(err, field.ErrDecrypt) || got != "" {
			t.Errorf("%s decrypted to %q, %v, want ErrDecrypt", name, got, err)
		}
	}
	for i := range raw {
		mut := append([]byte(nil), raw...)
		mut[i] ^= 0x01
		check("flip at "+string(rune('0'+i%10)), mut)
	}
	for n := 0; n < len(raw); n++ {
		check("truncation", raw[:n])
	}
	check("extension", append(append([]byte(nil), raw...), 0))
	for _, bad := range []string{"", "!!!", ct + "=", ct[:len(ct)-1]} {
		if _, err := s.fld.Decrypt(bad); !errors.Is(err, field.ErrDecrypt) {
			t.Errorf("Decrypt(%q) = %v, want ErrDecrypt", bad, err)
		}
	}
}

// Columns and deployments stay apart: the ciphertext of one column does not
// open in another and its index finds nothing there; another deployment shares
// neither.
func TestE2E_Field_columnsAndDeploymentsDoNotShareCiphertextsOrIndexes(t *testing.T) {
	e := hostiletest.NewEnv(t)
	email, phone := e.Field(t, "email"), e.Field(t, "phone")
	foreign := hostiletest.NewEnv(t).Field(t, "email")

	value := "alice@example.com"
	ct, _ := email.Encrypt(value)
	idx, _ := email.BlindIndex(value)

	if got, err := phone.Decrypt(ct); !errors.Is(err, field.ErrDecrypt) || got != "" {
		t.Errorf("the phone column opened an email ciphertext: %q, %v", got, err)
	}
	if got, err := foreign.Decrypt(ct); !errors.Is(err, field.ErrDecrypt) || got != "" {
		t.Errorf("another deployment opened this ciphertext: %q, %v", got, err)
	}
	if other, _ := phone.BlindIndex(value); other == idx {
		t.Error("two columns produced one index for one value")
	}
	if other, _ := foreign.BlindIndex(value); other == idx {
		t.Error("two deployments produced one index for one value")
	}
	// A module rebuilt on the same deployment and context is the same column.
	again := e.Field(t, "email")
	if got, err := again.Decrypt(ct); err != nil || got != value {
		t.Errorf("a rebuilt module = %q, %v, want the value", got, err)
	}
	if rebuilt, _ := again.BlindIndex(value); rebuilt != idx {
		t.Error("a rebuilt module computed another index")
	}
}

// Contexts that differ only by where a boundary sits (a name and its prefix,
// one with a NUL) never share an index or a ciphertext.
func TestE2E_Field_neighbouringContextsAreDistinctColumns(t *testing.T) {
	e := hostiletest.NewEnv(t)
	a, b := e.Field(t, "ab"), e.Field(t, "a")
	idxA, _ := a.BlindIndex("c")
	idxB, _ := b.BlindIndex("bc")
	if idxA == idxB {
		t.Error(`("ab","c") and ("a","bc") share an index`)
	}
	ct, _ := a.Encrypt("c")
	if _, err := b.Decrypt(ct); !errors.Is(err, field.ErrDecrypt) {
		t.Errorf("neighbouring context opened the ciphertext: %v", err)
	}
	nul := e.Field(t, "ab\x00")
	if idx, _ := nul.BlindIndex("c"); idx == idxA {
		t.Error("a context with a trailing NUL shares the index of the one without")
	}
}
