package candidate

// sentinelKey is a public key whose identity is its address, so a test can tell
// which candidate Pick returned even when every other field is equal.
type sentinelKey struct{ index int }

// Each byte of a fuzzed spec describes one candidate: two bits pick its alg,
// two its use and two its key_ops.
//
//	alg:     0 none, 1 the token's alg, 2 the token's alg plus a suffix, 3 "other"
//	use:     0 none, 1 "sig", 2 "enc", 3 "SIG"
//	key_ops: 0 none, 1 {verify}, 2 {encrypt}, 3 {sign, verify}
func specAlg(b byte, tokenAlg string) string {
	return [4]string{"", tokenAlg, tokenAlg + "-x", "other"}[b&3]
}

func specUse(b byte) string { return [4]string{"", "sig", "enc", "SIG"}[(b>>2)&3] }

func specKeyOps(b byte) map[string]struct{} {
	switch (b >> 4) & 3 {
	case 1:
		return map[string]struct{}{"verify": {}}
	case 2:
		return map[string]struct{}{"encrypt": {}}
	case 3:
		return map[string]struct{}{"sign": {}, "verify": {}}
	}
	return nil
}

// specCandidates builds the list a spec describes, each with its own key.
func specCandidates(spec []byte, tokenAlg string) []Candidate {
	list := make([]Candidate, len(spec))
	for i, b := range spec {
		list[i] = Candidate{
			Pub:    &sentinelKey{index: i},
			Alg:    specAlg(b, tokenAlg),
			Use:    specUse(b),
			KeyOps: specKeyOps(b),
			Issuer: string(rune('a' + i%26)),
		}
	}
	return list
}

// specFirstAllowed returns the index of the first candidate the restriction
// contract allows, or -1. It decides from the selector bits alone, never from
// the built candidate, so it does not share logic with Matches.
func specFirstAllowed(spec []byte, tokenAlg string) int {
	for i, b := range spec {
		algOK := b&3 <= 1 || (b&3 == 3 && tokenAlg == "other")
		useOK := (b>>2)&3 <= 1
		opsOK := (b>>4)&3 != 2
		if algOK && useOK && opsOK {
			return i
		}
	}
	return -1
}
