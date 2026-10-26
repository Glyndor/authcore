// Command username demonstrates the auth/username module: validating and
// normalizing usernames against the library's fixed rules.
package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/username"
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
	// Setup: initialise authcore and the username module.
	// username.New requires no extra arguments — all rules are fixed.
	// -------------------------------------------------------------------------
	dir, cleanup := tempDir()
	defer cleanup()

	auth, err := authcore.New(authcore.Config{KeysDir: dir})
	if err != nil {
		return fmt.Errorf("authcore: %w", err)
	}

	userMod, err := username.New(auth)
	if err != nil {
		return fmt.Errorf("username module: %w", err)
	}

	// -------------------------------------------------------------------------
	// Example 1: ValidateAndNormalize — the single entry point.
	// It lowercases, trims whitespace, and validates in one atomic step.
	// The returned string is the canonical form — always store and query this.
	// -------------------------------------------------------------------------
	fmt.Fprintln(w, "=== ValidateAndNormalize ===")

	cases := []string{
		"  Alice_123  ", // valid — normalized to lowercase + trimmed
		"bob-dev",       // valid — hyphen in middle
		"user99",        // valid
		"ab",            // invalid — too short (min 3)
		"-alice",        // invalid — starts with hyphen
		"alice__bob",    // invalid — consecutive underscores
		"alice@bob",     // invalid — @ not allowed
		"admin",         // invalid — reserved name
		"root",          // invalid — reserved name
		"login",         // invalid — reserved name (would clash with URL route)
	}

	for _, raw := range cases {
		normalized, err := userMod.ValidateAndNormalize(raw)
		if err != nil {
			// errors.Unwrap(err).Error() returns just the rule that failed —
			// safe to return directly in a 400 response.
			fmt.Fprintf(w, "rejected  %-20q → %s\n", raw, errors.Unwrap(err).Error())
		} else {
			fmt.Fprintf(w, "accepted  %-20q → %q\n", raw, normalized)
		}
	}

	// -------------------------------------------------------------------------
	// Example 2: registration flow.
	// Normalize once, store the canonical form, use it for every lookup.
	// -------------------------------------------------------------------------
	fmt.Fprintln(w, "\n=== Registration flow ===")

	raw := "  Alice_Dev99  " // user input from HTTP request
	normalized, err := userMod.ValidateAndNormalize(raw)
	if err != nil {
		fmt.Fprintf(w, "rejected: %v\n", errors.Unwrap(err))
		return nil
	}

	// Store normalized — always lowercase, trimmed, validated.
	// "  Alice_Dev99  " → "alice_dev99" — consistent for every future lookup.
	fmt.Fprintf(w, "raw input  : %q\n", raw)
	fmt.Fprintf(w, "stored as  : %q\n", normalized)

	// -------------------------------------------------------------------------
	// Example 3: error handling — ErrInvalidUsername wraps the specific reason.
	// -------------------------------------------------------------------------
	fmt.Fprintln(w, "\n=== Error handling ===")

	_, err = userMod.ValidateAndNormalize("admin")
	if errors.Is(err, username.ErrInvalidUsername) {
		fmt.Fprintf(w, "ErrInvalidUsername: %v\n", err)
		fmt.Fprintf(w, "reason only       : %v\n", errors.Unwrap(err)) // safe for 400 response
	}

	return nil
}

func tempDir() (string, func()) {
	dir, err := os.MkdirTemp("", "authcore-username-example-*")
	if err != nil {
		log.Fatalf("create temp dir: %v", err)
	}
	return dir, func() { _ = os.RemoveAll(dir) }
}
