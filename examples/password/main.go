// Command password demonstrates the auth/password module: hashing, verifying,
// and fail-fast policy validation.
package main

import (
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/password"
)

func main() {
	// -------------------------------------------------------------------------
	// Setup: initialise authcore and the password module.
	// password.New requires no extra arguments — OWASP defaults are applied.
	// -------------------------------------------------------------------------
	dir, cleanup := tempDir()
	defer cleanup()

	auth, err := authcore.New(authcore.Config{KeysDir: dir})
	if err != nil {
		log.Fatalf("authcore: %v", err)
	}

	pwdMod, err := password.New(auth)
	if err != nil {
		log.Fatalf("password module: %v", err)
	}

	// -------------------------------------------------------------------------
	// Example 1: fail-fast policy validation.
	// Call ValidatePolicy in your HTTP handler before hashing so you return a
	// 400 immediately without spending ~64 MiB of RAM on a weak password.
	// -------------------------------------------------------------------------
	fmt.Println("=== Policy validation ===")

	if err := pwdMod.ValidatePolicy("weak"); err != nil {
		fmt.Printf("rejected  : %v\n", err)
	}

	if err := pwdMod.ValidatePolicy("Str0ng-P@ssword!"); err == nil {
		fmt.Println("accepted  : Str0ng-P@ssword!")
	}

	// -------------------------------------------------------------------------
	// Example 2: hash a password.
	// Each call generates a fresh random 16-byte salt. The output is a
	// self-describing PHC string that embeds all parameters:
	//   $argon2id$v=19$m=65536,t=3,p=2$<salt>$<key>
	// Store the whole string in your database — nothing else is needed.
	// -------------------------------------------------------------------------
	fmt.Println("\n=== Hashing ===")

	hash, err := pwdMod.Hash("Str0ng-P@ssword!")
	if err != nil {
		log.Fatalf("hash: %v", err)
	}
	fmt.Printf("stored hash: %s\n", hash)

	// -------------------------------------------------------------------------
	// Example 3: verify a password against the stored hash.
	// Parameters are read from the hash itself, so old hashes stay valid even
	// after you tune Memory or Iterations for new users.
	// -------------------------------------------------------------------------
	fmt.Println("\n=== Verification ===")

	ok, err := pwdMod.Verify("Str0ng-P@ssword!", hash)
	if err != nil {
		log.Fatalf("verify: %v", err)
	}
	fmt.Printf("correct password : %v\n", ok) // true

	ok, err = pwdMod.Verify("WrongPassword1!", hash)
	if err != nil {
		log.Fatalf("verify: %v", err)
	}
	fmt.Printf("wrong password   : %v\n", ok) // false

	// -------------------------------------------------------------------------
	// Example 4: error handling — malformed hash.
	// -------------------------------------------------------------------------
	fmt.Println("\n=== Error handling ===")

	_, err = pwdMod.Verify("anything", "not-a-valid-phc-string")
	if errors.Is(err, password.ErrInvalidHash) {
		fmt.Println("ErrInvalidHash caught correctly")
	}

	// -------------------------------------------------------------------------
	// Example 5: custom work parameters.
	// Tune upward on hardware with more RAM/CPU to increase work factor over time.
	// -------------------------------------------------------------------------
	fmt.Println("\n=== Custom parameters ===")

	strongMod, err := password.New(auth, password.Config{
		Memory:      128 * 1024, // 128 MiB
		Iterations:  4,
		Parallelism: 4,
	})
	if err != nil {
		log.Fatalf("strong module: %v", err)
	}

	strongHash, err := strongMod.Hash("Str0ng-P@ssword!")
	if err != nil {
		log.Fatalf("strong hash: %v", err)
	}
	fmt.Printf("128 MiB hash: %s\n", strongHash)
}

func tempDir() (string, func()) {
	dir, err := os.MkdirTemp("", "authcore-password-example-*")
	if err != nil {
		log.Fatalf("create temp dir: %v", err)
	}
	return dir, func() { _ = os.RemoveAll(dir) }
}
