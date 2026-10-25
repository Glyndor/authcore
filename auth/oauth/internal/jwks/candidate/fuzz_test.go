package candidate

import (
	"errors"
	"strings"
	"testing"
)

// FuzzPick builds a candidate list from arbitrary alg, use and key_ops values
// and selects with an arbitrary token alg. The property is the restriction
// contract itself, checked from the outside: a candidate is returned only if
// the key allows the token's alg, is a signature key and may verify; and when
// some candidate does allow it, Pick does not refuse.
func FuzzPick(f *testing.F) {
	f.Add("RS256", "RS256", "sig", "verify,sign", "k1")
	f.Add("PS256", "RS256", "", "", "k1")
	f.Add("RS256", "", "enc", "", "")
	f.Add("RS256", "", "", "encrypt", "k\x00")
	f.Add("none", "none", "sig", "verify", "k1")

	errFetch := errors.New("fetch")
	f.Fuzz(func(t *testing.T, tokenAlg, keyAlg, use, ops, kid string) {
		var keyOps map[string]struct{}
		if ops != "" {
			keyOps = map[string]struct{}{}
			for _, op := range strings.Split(ops, ",") {
				keyOps[op] = struct{}{}
			}
		}
		// The strict candidate first, then a permissive one, so the case where
		// the first is skipped and a later one matches is exercised too.
		list := []Candidate{{Alg: keyAlg, Use: use, KeyOps: keyOps}, {}}

		allows := func(c Candidate) bool {
			_, canVerify := c.KeyOps["verify"]
			return (c.Alg == "" || c.Alg == tokenAlg) && (c.Use == "" || c.Use == "sig") && (len(c.KeyOps) == 0 || canVerify)
		}
		got, err := Pick(errFetch, list, kid, tokenAlg)
		if err != nil {
			if !errors.Is(err, errFetch) {
				t.Fatalf("a refusal that does not wrap the fetch sentinel: %v", err)
			}
			if allows(list[0]) || allows(list[1]) {
				t.Fatal("refused although a candidate allows this algorithm")
			}
			return
		}
		if !allows(got) {
			t.Fatalf("selected a candidate that does not allow alg %q: %+v", tokenAlg, got)
		}
		if allows(list[0]) && got.Alg != list[0].Alg {
			t.Fatal("skipped the first candidate although it allows the algorithm")
		}
	})
}
