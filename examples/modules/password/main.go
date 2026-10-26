// Command password demonstrates the auth/password module: hashing, verifying,
// and fail-fast policy validation.
package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/password"
)

func main() {
	if err := run(os.Stdout); err != nil {
		log.Fatal(err)
	}
}

// run is the whole example. It writes to w, so the tests read what a user would
// see, and returns an error where the demo used to exit.
func run(w io.Writer) error {
	// -------------------------------------------------------------------------
	// Setup: initialise authcore and the password module.
	// password.New requires no extra arguments — OWASP defaults are applied.
	// -------------------------------------------------------------------------
	dir, cleanup := tempDir()
	defer cleanup()

	auth, err := authcore.New(authcore.Config{KeysDir: dir})
	if err != nil {
		return fmt.Errorf("authcore: %w", err)
	}

	pwdMod, err := password.New(auth)
	if err != nil {
		return fmt.Errorf("password module: %w", err)
	}

	// -------------------------------------------------------------------------
	// Example 1: fail-fast policy validation.
	// Call ValidatePolicy in your HTTP handler before hashing so you return a
	// 400 immediately without spending ~64 MiB of RAM on a weak password.
	// -------------------------------------------------------------------------
	fmt.Fprintln(w, "=== Policy validation ===")

	if err := pwdMod.ValidatePolicy("weak"); err != nil {
		fmt.Fprintf(w, "rejected  : %v\n", err)
	}

	if err := pwdMod.ValidatePolicy("Str0ng-P@ssword!"); err == nil {
		fmt.Fprintln(w, "accepted  : Str0ng-P@ssword!")
	}

	// -------------------------------------------------------------------------
	// Example 2: hash a password.
	// Each call generates a fresh random 16-byte salt. The output is a
	// self-describing PHC string that embeds all parameters:
	//   $argon2id$v=19$m=65536,t=3,p=2$<salt>$<key>
	// Store the whole string in your database — nothing else is needed.
	// -------------------------------------------------------------------------
	fmt.Fprintln(w, "\n=== Hashing ===")

	hash, err := pwdMod.Hash("Str0ng-P@ssword!")
	if err != nil {
		return fmt.Errorf("hash: %w", err)
	}
	fmt.Fprintf(w, "stored hash: %s\n", hash)

	// -------------------------------------------------------------------------
	// Example 3: verify a password against the stored hash.
	// Parameters are read from the hash itself, so old hashes stay valid even
	// after you tune Memory or Iterations for new users.
	// -------------------------------------------------------------------------
	fmt.Fprintln(w, "\n=== Verification ===")

	ok, err := pwdMod.Verify("Str0ng-P@ssword!", hash)
	if err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	fmt.Fprintf(w, "correct password : %v\n", ok) // true

	ok, err = pwdMod.Verify("WrongPassword1!", hash)
	if err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	fmt.Fprintf(w, "wrong password   : %v\n", ok) // false

	// -------------------------------------------------------------------------
	// Example 4: error handling — malformed hash.
	// -------------------------------------------------------------------------
	fmt.Fprintln(w, "\n=== Error handling ===")

	_, err = pwdMod.Verify("anything", "not-a-valid-phc-string")
	if errors.Is(err, password.ErrInvalidHash) {
		fmt.Fprintln(w, "ErrInvalidHash caught correctly")
	}

	// -------------------------------------------------------------------------
	// Example 5: custom work parameters.
	// Tune upward on hardware with more RAM/CPU to increase work factor over time.
	// -------------------------------------------------------------------------
	fmt.Fprintln(w, "\n=== Custom parameters ===")

	strongMod, err := password.New(auth, password.Config{
		Memory:      128 * 1024, // 128 MiB
		Iterations:  4,
		Parallelism: 4,
	})
	if err != nil {
		return fmt.Errorf("strong module: %w", err)
	}

	strongHash, err := strongMod.Hash("Str0ng-P@ssword!")
	if err != nil {
		return fmt.Errorf("strong hash: %w", err)
	}
	fmt.Fprintf(w, "128 MiB hash: %s\n", strongHash)

	return nil
}

func tempDir() (string, func()) {
	dir, err := os.MkdirTemp("", "authcore-password-example-*")
	if err != nil {
		log.Fatalf("create temp dir: %v", err)
	}
	return dir, func() { _ = os.RemoveAll(dir) }
}
