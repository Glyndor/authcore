package kdf_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/password/internal/kdf"
	"github.com/Glyndor/authcore/auth/password/internal/phc"
)

var cheap = phc.Params{Memory: phc.MinMemory, Iterations: 1, Parallelism: 1}

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
	ok, err := kdf.Verify("Correct-Horse-9!", h)
	if err != nil || !ok {
		t.Fatalf("Verify(correct) = %v, %v; want true, nil", ok, err)
	}
	ok, err = kdf.Verify("Wrong-Horse-9!", h)
	if err != nil || ok {
		t.Fatalf("Verify(wrong) = %v, %v; want false, nil", ok, err)
	}
}

// A hash the parser refuses never reaches the key derivation, and the error
// carries the phc sentinel the password package maps to ErrInvalidHash.
func TestVerifyRefusesAMalformedHash(t *testing.T) {
	ok, err := kdf.Verify("anything", "not-a-phc-string")
	if ok {
		t.Error("Verify of a malformed hash returned true")
	}
	if !errors.Is(err, phc.ErrInvalid) {
		t.Errorf("Verify error = %v, want it to wrap phc.ErrInvalid", err)
	}
}
