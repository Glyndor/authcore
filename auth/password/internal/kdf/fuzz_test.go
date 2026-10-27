package kdf_test

import (
	"errors"
	"testing"

	"github.com/Glyndor/authcore/auth/password/internal/kdf"
	"github.com/Glyndor/authcore/auth/password/internal/phc"
)

// fuzzDeriveBudget bounds the work the fuzzer may let argon2 do in one
// input, in KiB-passes (memory times iterations). It is small on purpose:
// what this target measures is the guard that refuses an expensive stored
// hash, and the guard is checked before any key is derived, so the inputs
// that reach the derivation are the cheap ones.
const fuzzDeriveBudget = 1 << 14

// fuzzParsable reports whether the cost is one the PHC parser accepts at
// all: a stored hash outside these bounds is refused by the parser, not by
// the ceiling, so the target has nothing to say about it.
func fuzzParsable(params phc.Params, ceiling phc.Params) bool {
	return params.Memory >= phc.MinMemory && params.Memory <= 1<<21 &&
		params.Iterations >= 1 && params.Iterations <= phc.MaxIterations &&
		params.Parallelism >= 1 && params.Parallelism <= 8 &&
		ceiling.Memory <= 1<<21 && ceiling.Iterations <= phc.MaxIterations
}

// FuzzVerifyWorkCeiling drives the work ceiling of Verify: the product of
// the memory and the iterations a stored hash carries must not exceed the
// work the module accepts, whatever the cost factors are one by one.
//
// The hash under test is built by this fuzz target, so its cost is known
// exactly. The contract: a hash whose cost exceeds the ceiling, or whose
// product exceeds the work the module accepts, is refused with the invalid
// hash sentinel and no key is derived; a hash within both is accepted, the
// made-up key it carries never matches, and a hash written with the same
// cost does match.
func FuzzVerifyWorkCeiling(f *testing.F) {
	salt := make([]byte, phc.SaltLen)
	key := make([]byte, phc.KeyLen)
	const plaintext = "Correct-Horse-Battery-Staple"

	// (memory, iterations, parallelism, maxWork, ceiling memory, ceiling iterations, ceiling parallelism)
	f.Add(uint32(phc.MinMemory), uint32(1), uint8(1), uint64(phc.MinMemory), uint32(1<<20), uint32(phc.MaxIterations), uint8(255))
	f.Add(uint32(phc.MinMemory), uint32(1), uint8(1), uint64(phc.MinMemory-1), uint32(1<<20), uint32(phc.MaxIterations), uint8(255))
	f.Add(uint32(phc.MinMemory), uint32(2), uint8(2), uint64(phc.MinMemory*2), uint32(1<<20), uint32(phc.MaxIterations), uint8(255))
	f.Add(uint32(phc.MinMemory), uint32(2), uint8(2), uint64(phc.MinMemory*2-1), uint32(1<<20), uint32(phc.MaxIterations), uint8(255))
	// A hash of one gigabyte, one pass over the product cap: refused, and
	// refused without allocating the gigabyte.
	f.Add(uint32(1<<20), uint32(5), uint8(16), uint64(1<<20*4), uint32(1<<20), uint32(phc.MaxIterations), uint8(255))
	f.Add(uint32(1<<20), uint32(20), uint8(16), uint64(1<<20*4), uint32(1<<20), uint32(phc.MaxIterations), uint8(255))
	// Above the memory ceiling, above the iteration ceiling, above the
	// parallelism ceiling.
	f.Add(uint32(1<<20), uint32(1), uint8(1), uint64(1<<62), uint32(1<<19), uint32(phc.MaxIterations), uint8(255))
	f.Add(uint32(phc.MinMemory), uint32(3), uint8(1), uint64(1<<62), uint32(1<<20), uint32(1), uint8(255))
	f.Add(uint32(phc.MinMemory), uint32(1), uint8(1), uint64(1<<62), uint32(1<<20), uint32(1), uint8(255))
	f.Add(uint32(phc.MinMemory), uint32(1), uint8(9), uint64(1<<62), uint32(1<<20), uint32(phc.MaxIterations), uint8(8))

	f.Fuzz(func(t *testing.T, memory, iterations uint32, parallelism uint8, maxWork uint64, ceilMemory, ceilIterations uint32, ceilParallelism uint8) {
		params := phc.Params{Memory: memory, Iterations: iterations, Parallelism: parallelism}
		ceiling := phc.Params{Memory: ceilMemory, Iterations: ceilIterations, Parallelism: ceilParallelism}
		work := uint64(memory) * uint64(iterations)
		overCeiling := memory > ceilMemory || iterations > ceilIterations || parallelism > ceilParallelism
		overWork := work > maxWork

		if !fuzzParsable(params, ceiling) {
			t.Skip()
		}
		if !overCeiling && !overWork && work > fuzzDeriveBudget {
			// Deriving a key here would make the fuzzer allocate hundreds of
			// megabytes per input. The guard, not the derivation, is what
			// this target measures.
			t.Skip()
		}

		hash := phc.Encode(params, salt, key)
		ok, err := kdf.Verify(plaintext, hash, ceiling, maxWork)

		switch {
		case overCeiling || overWork:
			if err == nil {
				t.Fatalf("accepted %+v: work %d, maxWork %d, ceiling %+v", params, work, maxWork, ceiling)
			}
			if !errors.Is(err, phc.ErrInvalid) {
				t.Fatalf("refused %+v with %v, want the invalid hash sentinel", params, err)
			}
			if ok {
				t.Fatalf("verified %+v, which the ceiling refuses", params)
			}
		default:
			if err != nil {
				t.Fatalf("refused %+v, which is within the ceiling %+v and the work %d: %v", params, ceiling, maxWork, err)
			}
			if ok {
				t.Fatalf("verified %+v against a key that was never derived", params)
			}
			// And a hash written with the same cost does verify: the
			// ceiling must not swallow the hashes the module writes itself.
			real, herr := kdf.Hash(plaintext, params)
			if herr != nil {
				t.Fatalf("Hash(%+v): %v", params, herr)
			}
			if ok, err := kdf.Verify(plaintext, real, ceiling, maxWork); err != nil || !ok {
				t.Fatalf("Verify of a hash written with %+v: ok = %v, err = %v; want true, nil", params, ok, err)
			}
		}
	})
}

// The fixture the target builds must be a hash the parser accepts, or every
// input would be refused by the parser instead of by the ceiling.
func TestFuzzFixtureIsAParsableHash(t *testing.T) {
	salt := make([]byte, phc.SaltLen)
	key := make([]byte, phc.KeyLen)
	params := phc.Params{Memory: 16 * 1024, Iterations: 2, Parallelism: 1}
	hash := phc.Encode(params, salt, key)
	got, gotSalt, gotKey, err := phc.Parse(hash)
	if err != nil {
		t.Fatalf("the fixture %q does not parse: %v", hash, err)
	}
	if got != params {
		t.Errorf("the fixture carries the cost %+v, want %+v", got, params)
	}
	if len(gotSalt) != phc.SaltLen || len(gotKey) != phc.KeyLen {
		t.Errorf("the fixture carries a salt of %d bytes and a key of %d bytes, want %d and %d", len(gotSalt), len(gotKey), phc.SaltLen, phc.KeyLen)
	}
	// The key of the fixture is made up, so it must not verify.
	if ok, err := kdf.Verify("Correct-Horse-Battery-Staple", hash, params, uint64(params.Memory)*uint64(params.Iterations)); ok || err != nil {
		t.Errorf("the made-up key of the fixture verified: ok = %v, err = %v", ok, err)
	}
}
