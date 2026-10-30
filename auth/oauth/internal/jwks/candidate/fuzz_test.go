package candidate

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

// FuzzPick builds a candidate list of fuzzed length and order, each entry with
// its own key and its own alg, use and key_ops, and selects with an arbitrary
// token alg. The property is the restriction contract itself, decided from a
// table independent of Matches: Pick returns the first candidate the table
// allows, whole and with its own key, and when none is allowed, including for
// an empty list, it refuses with an error that wraps the fetch sentinel.
func FuzzPick(f *testing.F) {
	f.Add("RS256", "k1", []byte{0x01, 0x00})       // strict first, permissive second
	f.Add("PS256", "k1", []byte{0x02, 0x00})       // first key declares another alg
	f.Add("RS256", "", []byte{})                   // no candidates
	f.Add("RS256", "k1", []byte{0x08, 0x20, 0x08}) // none is allowed
	f.Add("RS256", "k1", []byte{0x00, 0x00})       // two permissive, distinct keys
	f.Add("other", "k\x00", []byte{0x03, 0x1c})    // alg "other" is the token's
	f.Add("none", "k1", []byte{0x31, 0x01})        // verify among the key_ops

	errFetch := errors.New("fetch")
	f.Fuzz(func(t *testing.T, tokenAlg, kid string, spec []byte) {
		if len(spec) > 64 {
			t.Skip()
		}
		list := specCandidates(spec, tokenAlg)
		want := specFirstAllowed(spec, tokenAlg)
		got, err := Pick(errFetch, list, kid, tokenAlg)
		if want < 0 {
			if !errors.Is(err, errFetch) {
				t.Fatalf("no candidate allows alg %q, got %+v, %v", tokenAlg, got, err)
			}
			if !reflect.DeepEqual(got, Candidate{}) {
				t.Fatalf("a candidate was returned alongside a refusal: %+v", got)
			}
			if strings.Contains(err.Error(), "for kid") != (kid != "") {
				t.Fatalf("the refusal does not name the kid exactly when one was given: %v", err)
			}
			return
		}
		if err != nil {
			t.Fatalf("refused although candidate %d allows alg %q: %v", want, tokenAlg, err)
		}
		if got.Pub != list[want].Pub || !reflect.DeepEqual(got, list[want]) {
			t.Fatalf("selected %+v, want candidate %d: %+v", got, want, list[want])
		}
	})
}
