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
		ok, err := kdf.Verify("Correct-Horse-9!", h, c)
		if ok || !errors.Is(err, phc.ErrInvalid) {
			t.Errorf("%s above the ceiling: Verify = %v, %v; want false, phc.ErrInvalid", name, ok, err)
		}
	}
	at := phc.Params{Memory: phc.MinMemory, Iterations: 2, Parallelism: 2}
	if ok, err := kdf.Verify("Correct-Horse-9!", h, at); err != nil || !ok {
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
	ok, err := kdf.Verify("Correct-Horse-9!", h, ceiling)
	if err != nil || !ok {
		t.Fatalf("Verify(correct) = %v, %v; want true, nil", ok, err)
	}
	ok, err = kdf.Verify("Wrong-Horse-9!", h, ceiling)
	if err != nil || ok {
		t.Fatalf("Verify(wrong) = %v, %v; want false, nil", ok, err)
	}
}

// A hash the parser refuses never reaches the key derivation, and the error
// carries the phc sentinel the password package maps to ErrInvalidHash.
func TestVerifyRefusesAMalformedHash(t *testing.T) {
	ok, err := kdf.Verify("anything", "not-a-phc-string", ceiling)
	if ok {
		t.Error("Verify of a malformed hash returned true")
	}
	if !errors.Is(err, phc.ErrInvalid) {
		t.Errorf("Verify error = %v, want it to wrap phc.ErrInvalid", err)
	}
}
