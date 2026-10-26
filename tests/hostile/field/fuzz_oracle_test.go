package field_test

import (
	"encoding/base64"
	"testing"

	"github.com/Glyndor/authcore/auth/field"
)

// FuzzOracleAgreement drives the module and the independent oracle with the
// same arbitrary context and plaintext. They must agree in both directions on
// the ciphertext and on the blind index, and one corrupted byte anywhere in the
// stored value must be refused.
func FuzzOracleAgreement(f *testing.F) {
	pepper := randomPepper(f)
	d := &deployment{t: f, pepper: pepper, prov: newProviderWithPepper(f, pepper)}
	for _, seed := range []struct{ context, plain string }{
		{"email", "alice@example.com"}, {"\x00", ""}, {"c", "\x00\x00\x00\x01"},
		{"users.phone", "+15555550100"}, {"\xff\xfe", "\xff"},
	} {
		f.Add(seed.context, seed.plain, uint16(0))
	}

	f.Fuzz(func(t *testing.T, context, plain string, flip uint16) {
		if context == "" {
			t.Skip("an empty context is refused at construction")
		}
		m, err := field.New(d.prov, field.Config{Context: context})
		if err != nil {
			t.Fatalf("New(%q): %v", context, err)
		}
		o := newOracle(t, pepper, context)

		ct, err := m.Encrypt(plain)
		if err != nil {
			t.Fatal(err)
		}
		if got, ok := o.open(ct); !ok || got != plain {
			t.Fatal("the oracle cannot open the module's ciphertext")
		}
		if got, err := m.Decrypt(o.seal(plain)); err != nil || got != plain {
			t.Fatalf("the module cannot open the oracle's ciphertext: %v", err)
		}
		if mustIndex(t, m, plain) != o.blindIndex(plain) {
			t.Fatal("BlindIndex disagrees with the oracle")
		}

		raw, _ := base64.RawStdEncoding.DecodeString(ct)
		raw[int(flip)%len(raw)] ^= 1 << (flip % 8)
		if got, err := m.Decrypt(base64.RawStdEncoding.EncodeToString(raw)); got != "" || err != field.ErrDecrypt {
			t.Fatalf("a corrupted value opened: %q, %v", got, err)
		}
	})
}

// FuzzBlindIndexBoundary asks whether two different (context, value) pairs ever
// share an index. The pairs are built so that they concatenate to the same
// bytes, which is the collision a separator-based encoding would allow.
func FuzzBlindIndexBoundary(f *testing.F) {
	pepper := randomPepper(f)
	d := &deployment{t: f, pepper: pepper, prov: newProviderWithPepper(f, pepper)}
	f.Add("email", "user@x", 3)
	f.Add("a", "bc", 1)
	f.Add("\x00\x00\x00\x01a", "b", 4)

	f.Fuzz(func(t *testing.T, context, value string, cut int) {
		joined := context + value
		if joined == "" || len(joined) < 2 {
			t.Skip()
		}
		if cut < 0 {
			cut = -cut
		}
		cut = cut%(len(joined)-1) + 1 // a split of the joined bytes, never empty on the left
		altContext, altValue := joined[:cut], joined[cut:]
		if context == "" || (altContext == context && altValue == value) {
			t.Skip()
		}
		a, err := field.New(d.prov, field.Config{Context: context})
		if err != nil {
			t.Fatal(err)
		}
		b, err := field.New(d.prov, field.Config{Context: altContext})
		if err != nil {
			t.Fatal(err)
		}
		if mustIndex(t, a, value) == mustIndex(t, b, altValue) {
			t.Fatalf("(%q,%q) and (%q,%q) share a blind index", context, value, altContext, altValue)
		}
	})
}
