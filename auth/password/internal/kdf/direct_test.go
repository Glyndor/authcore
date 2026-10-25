package kdf_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/password/internal/kdf"
	"github.com/Glyndor/authcore/auth/password/internal/phc"
)

var cheap = phc.Params{Memory: phc.MinMemory, Iterations: 1, Parallelism: 1}

var ceiling = phc.Params{Memory: phc.MinMemory, Iterations: 1, Parallelism: 1}

// noWorkCap leaves the Memory x Iterations product out of the way for the tests
// that exercise the per-parameter ceilings.
const noWorkCap = 1 << 62

// A parameter above the ceiling is refused with the phc sentinel, one at a time,
// and a hash exactly at the ceiling still verifies.
func TestVerifyRefusesCostAboveTheCeiling(t *testing.T) {
	h, err := kdf.Hash("Correct-Horse-9!", phc.Params{Memory: phc.MinMemory, Iterations: 2, Parallelism: 2})
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	for name, c := range map[string]phc.Params{
		"memory":      {Memory: phc.MinMemory - 1, Iterations: 2, Parallelism: 2},
		"iterations":  {Memory: phc.MinMemory, Iterations: 1, Parallelism: 2},
		"parallelism": {Memory: phc.MinMemory, Iterations: 2, Parallelism: 1},
	} {
		ok, err := kdf.Verify("Correct-Horse-9!", h, c, noWorkCap)
		if ok || !errors.Is(err, phc.ErrInvalid) {
			t.Errorf("%s above the ceiling: Verify = %v, %v; want false, phc.ErrInvalid", name, ok, err)
		}
	}
	at := phc.Params{Memory: phc.MinMemory, Iterations: 2, Parallelism: 2}
	if ok, err := kdf.Verify("Correct-Horse-9!", h, at, noWorkCap); err != nil || !ok {
		t.Errorf("at the ceiling: Verify = %v, %v; want true, nil", ok, err)
	}
}

// Hash and Verify agree with each other without the password package in
// between: the parameters come back out of the string Hash wrote.
func TestHashThenVerify(t *testing.T) {
	h, err := kdf.Hash("Correct-Horse-9!", cheap)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=8192,t=1,p=1$") {
		t.Errorf("Hash = %q, want the cost parameters in the PHC prefix", h)
	}
	ok, err := kdf.Verify("Correct-Horse-9!", h, ceiling, noWorkCap)
	if err != nil || !ok {
		t.Fatalf("Verify(correct) = %v, %v; want true, nil", ok, err)
	}
	ok, err = kdf.Verify("Wrong-Horse-9!", h, ceiling, noWorkCap)
	if err != nil || ok {
		t.Fatalf("Verify(wrong) = %v, %v; want false, nil", ok, err)
	}
}

// A hash the parser refuses never reaches the key derivation, and the error
// carries the phc sentinel the password package maps to ErrInvalidHash.
func TestVerifyRefusesAMalformedHash(t *testing.T) {
	ok, err := kdf.Verify("anything", "not-a-phc-string", ceiling, noWorkCap)
	if ok {
		t.Error("Verify of a malformed hash returned true")
	}
	if !errors.Is(err, phc.ErrInvalid) {
		t.Errorf("Verify error = %v, want it to wrap phc.ErrInvalid", err)
	}
}

// The product of Memory and Iterations is capped on its own: each factor can
// sit under its ceiling and the hash is still refused, while a hash exactly at
// the cap verifies.
func TestVerifyRefusesMemoryTimesIterationsAboveTheCap(t *testing.T) {
	p := phc.Params{Memory: phc.MinMemory, Iterations: 3, Parallelism: 1}
	h, err := kdf.Hash("Correct-Horse-9!", p)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	loose := phc.Params{Memory: phc.MaxMemory, Iterations: phc.MaxIterations, Parallelism: 255}
	work := uint64(p.Memory) * uint64(p.Iterations)
	ok, err := kdf.Verify("Correct-Horse-9!", h, loose, work-1)
	if ok || !errors.Is(err, phc.ErrInvalid) {
		t.Errorf("one below the product: Verify = %v, %v; want false, phc.ErrInvalid", ok, err)
	}
	if ok, err := kdf.Verify("Correct-Horse-9!", h, loose, work); err != nil || !ok {
		t.Errorf("at the product: Verify = %v, %v; want true, nil", ok, err)
	}
}
