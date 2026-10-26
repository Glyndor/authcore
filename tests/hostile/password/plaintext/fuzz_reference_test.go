package plaintext

import (
	"testing"

	"golang.org/x/text/unicode/norm"

	"github.com/Glyndor/authcore/auth/password"
	"github.com/Glyndor/authcore/tests/hostile/password/hostiletest"
)

// FuzzVerifyMatchesReferenceArgon2 hashes arbitrary bytes with the reference
// implementation and requires the module to verify them, under a cost chosen
// from the input, and to refuse the same input with one byte appended. Verify
// applies no policy, so any bytes are a legal plaintext, valid UTF-8 or not.
func FuzzVerifyMatchesReferenceArgon2(f *testing.F) {
	m := hostiletest.NewModule(f, password.Config{Memory: 8 * 1024, Iterations: 1, Parallelism: 1})
	for _, s := range []string{"", "a", hostiletest.Strong, "Café", "Cafe\u0301", "\x00", "\xff\xfe", "\U0001f600", "Å", "ﬁ"} {
		f.Add(s, uint8(0), uint8(0))
	}
	f.Add(hostiletest.Strong, uint8(2), uint8(3))
	f.Add("x", uint8(7), uint8(7))

	f.Fuzz(func(t *testing.T, plaintext string, passes, lanes uint8) {
		if len(plaintext) > 4096 {
			return
		}
		it, par := 1+uint32(passes%8), 1+lanes%8 // inside the ceiling of a floor-cost module
		hash := hostiletest.RefHash(plaintext, 8192, it, par, []byte("fuzz-salt-123456"))
		ok, err := m.Verify(plaintext, hash)
		if err != nil || !ok {
			t.Fatalf("Verify(%q) against the reference hash (t=%d, p=%d) = %v, %v", plaintext, it, par, ok, err)
		}
		if norm.NFC.String(plaintext+"\x01") != norm.NFC.String(plaintext) {
			if ok, _ := m.Verify(plaintext+"\x01", hash); ok {
				t.Fatalf("%q plus a byte verified against the hash of %q", plaintext, plaintext)
			}
		}
	})
}

// FuzzNormalisationEquivalence requires that two spellings of a password verify
// each other exactly when their NFC forms are equal, for every spelling the
// fuzzer can build from the four Unicode forms. The relaxed policy lets the
// fuzzer reach the normaliser instead of stopping at the policy.
func FuzzNormalisationEquivalence(f *testing.F) {
	m := hostiletest.NewModule(f, hostiletest.Relaxed(64))
	for _, s := range normalizationSamples {
		f.Add(s, uint8(0), uint8(1))
	}
	f.Add("Cafe\u0301 pass 12", uint8(1), uint8(0))
	f.Add("각 pass 123", uint8(0), uint8(2))

	forms := []norm.Form{norm.NFC, norm.NFD, norm.NFKC, norm.NFKD}
	f.Fuzz(func(t *testing.T, plaintext string, storeForm, tryForm uint8) {
		stored := forms[int(storeForm)%4].String(plaintext)
		hash, err := m.Hash(stored)
		if err != nil {
			return // refused by the policy: nothing to compare
		}
		attempt := forms[int(tryForm)%4].String(plaintext)
		ok, err := m.Verify(attempt, hash)
		if err != nil {
			t.Fatalf("Verify(%q) against its own hash: %v", attempt, err)
		}
		if want := norm.NFC.String(attempt) == norm.NFC.String(stored); ok != want {
			t.Fatalf("stored %q, attempt %q: verified = %v, want %v", stored, attempt, ok, want)
		}
	})
}
