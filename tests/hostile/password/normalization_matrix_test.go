package password_test

import (
	"testing"

	"golang.org/x/text/unicode/norm"
)

// Passwords where the four Unicode forms differ, or where composition has
// exceptions. Each is hashed in one form and verified in every form.
var normalizationSamples = []string{
	"Café Muñoz 99",        // precomposed accents
	"Café Muñoz 99",      // the same, decomposed
	"Ångström Å 12",        // letter A-ring and ANGSTROM SIGN
	"Ohm Ω and omega Ω 34", // OHM SIGN, a singleton decomposition
	"ﬁne ﬂour ﬃx 56",       // ligatures: only compatibility forms fold them
	"Ｐａｓｓｗｏｒｄ 78",          // fullwidth letters
	"x² + y³ = z⁴ 90",      // superscripts
	"각 각 hangul 12",      // conjoining jamo and the syllable they compose to
	"क़क क़ 34",             // composition exclusion: U+0958 does not recompose
	"ẛ̣ and ẛ 56",          // long s with dot, canonical reordering of marks
	"ậ vs ậ 78",        // marks in two orders, one canonical order
	"½ cup ⅕ cup 90",       // vulgar fractions
	"① ❶ circled 12",       // circled digits
	"㎒ mhz ㎯ rad 34",       // squared CJK compatibility
}

// Two spellings of a password are one password exactly when their NFC forms are
// equal. The module hashes the NFC form and nothing coarser, in both Hash and
// Verify, so for every pair drawn from the forms of every sample, verification
// agrees with that rule. A module that normalised only one side, or folded
// compatibility forms, breaks it.
func TestHostile_NormalizationMatrix_verifyAgreesWithNFCEquality(t *testing.T) {
	m := newModule(t, relaxed(64))
	forms := map[string]norm.Form{"NFC": norm.NFC, "NFD": norm.NFD, "NFKC": norm.NFKC, "NFKD": norm.NFKD}

	spellings := func(s string) []string {
		out := []string{s}
		for _, f := range forms {
			out = append(out, f.String(s))
		}
		return out
	}
	// Each sample is hashed once, in each of its spellings in turn, and
	// verified against every spelling of itself and of the next sample (so a
	// wrong "yes" and a wrong "no" are both reachable).
	for i, sample := range normalizationSamples {
		next := normalizationSamples[(i+1)%len(normalizationSamples)]
		seen := map[string]bool{}
		var attempts []string
		for _, a := range append(spellings(sample), spellings(next)...) {
			if !seen[a] {
				seen[a] = true
				attempts = append(attempts, a)
			}
		}
		// The stored spelling alternates, so the whole matrix is covered
		// across the samples without hashing every sample three times.
		stored := []string{sample, norm.NFD.String(sample), norm.NFKC.String(sample)}[i%3]
		{
			hash, err := m.Hash(stored)
			if err != nil {
				t.Fatalf("Hash(%q): %v", stored, err)
			}
			for _, attempt := range attempts {
				want := norm.NFC.String(attempt) == norm.NFC.String(stored)
				ok, err := m.Verify(attempt, hash)
				if err != nil {
					t.Fatalf("Verify(%q): %v", attempt, err)
				}
				if ok != want {
					t.Errorf("hash of %q, attempt %q: verified = %v, want %v", stored, attempt, ok, want)
				}
			}
		}
	}
}

// The facts the matrix rests on, stated by hand so that a change in the
// normalisation tables cannot silently redefine them: these pairs are one
// password, and these are not.
func TestHostile_NormalizationMatrix_knownPairs(t *testing.T) {
	m := newModule(t, relaxed(64))
	same := [][2]string{
		{"Café pass 12", "Café pass 12"},
		{"Ångstrom 123", "Ångstrom 123"},
		{"Omega Ω pass1", "Omega Ω pass1"},
		{"각 pass123", "각 pass123"},
		{"ậ pass12", "ậ pass12"},
	}
	different := [][2]string{
		{"ﬁne passw0rd", "fine passw0rd"},
		{"Ｐassword 123", "Password 123"},
		{"x² passwor1", "x2 passwor1"},
		{"½ pass word", "1⁄2 pass word"},
		{"① pass word", "1 pass word"},
	}
	for _, p := range same {
		h, err := m.Hash(p[0])
		if err != nil {
			t.Fatalf("Hash(%q): %v", p[0], err)
		}
		if ok, _ := m.Verify(p[1], h); !ok {
			t.Errorf("%q and %q should be one password", p[0], p[1])
		}
	}
	for _, p := range different {
		h, err := m.Hash(p[0])
		if err != nil {
			t.Fatalf("Hash(%q): %v", p[0], err)
		}
		if ok, _ := m.Verify(p[1], h); ok {
			t.Errorf("%q and %q should be two passwords", p[0], p[1])
		}
	}
}
