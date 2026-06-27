// Command email demonstrates the auth/email module: validating, normalizing,
// and optionally verifying that an email domain can receive messages via DNS MX lookup.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/email"
)

func main() {
	// -------------------------------------------------------------------------
	// Setup: initialise authcore and the email module.
	// Close() stops the background cache eviction goroutine — always defer it.
	// -------------------------------------------------------------------------
	dir, cleanup := tempDir()
	defer cleanup()

	auth, err := authcore.New(authcore.Config{KeysDir: dir})
	if err != nil {
		log.Fatalf("authcore: %v", err)
	}

	emailMod, err := email.New(auth)
	if err != nil {
		log.Fatalf("email module: %v", err)
	}
	defer emailMod.Close()

	// -------------------------------------------------------------------------
	// Example 1: ValidateAndNormalize — the single entry point.
	// It lowercases, trims whitespace, and validates in one atomic step.
	// The returned string is the canonical form — always store and query this.
	// -------------------------------------------------------------------------
	fmt.Println("=== ValidateAndNormalize ===")

	cases := []string{
		"  USER@EXAMPLE.COM  ",            // valid — normalized to lowercase + trimmed
		"user.name+tag@sub.example.co.uk", // valid — complex but correct
		"",                                // invalid — empty
		"notanemail",                      // invalid — no @
		"user@localhost",                  // invalid — domain has no dot
		"user@example..com",               // invalid — consecutive dots
	}

	for _, raw := range cases {
		normalized, err := emailMod.ValidateAndNormalize(raw)
		if err != nil {
			// errors.Unwrap(err).Error() returns just the rule that failed —
			// safe to return directly in a 400 response.
			fmt.Printf("rejected  %q → %s\n", raw, errors.Unwrap(err).Error())
		} else {
			fmt.Printf("accepted  %q → %q\n", raw, normalized)
		}
	}

	// -------------------------------------------------------------------------
	// Example 2: VerifyDomain — optional DNS MX check.
	// Always call ValidateAndNormalize first. Use a short context timeout to
	// avoid blocking your registration endpoint on a slow DNS resolver.
	//
	// ErrDomainNoMX        → CLIENT-SAFE, return 400.
	// ErrDomainUnresolvable → soft failure, log and let the user proceed.
	// -------------------------------------------------------------------------
	fmt.Println("\n=== VerifyDomain ===")

	normalized, _ := emailMod.ValidateAndNormalize("user@gmail.com")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err = emailMod.VerifyDomain(ctx, normalized)
	switch {
	case err == nil:
		fmt.Printf("domain OK     : %s\n", normalized)
	case errors.Is(err, email.ErrDomainNoMX):
		// Domain exists but cannot receive email — safe to tell the user.
		fmt.Printf("no MX records : %s\n", normalized)
	case errors.Is(err, email.ErrDomainUnresolvable):
		// DNS lookup failed — do NOT block the user, log and continue.
		fmt.Printf("DNS unavailable (soft failure): %v\n", err)
	}

	// -------------------------------------------------------------------------
	// Example 3: error handling — ErrInvalidEmail wraps the specific reason.
	// -------------------------------------------------------------------------
	fmt.Println("\n=== Error handling ===")

	_, err = emailMod.ValidateAndNormalize("bad@@email")
	if errors.Is(err, email.ErrInvalidEmail) {
		fmt.Printf("ErrInvalidEmail: %v\n", err)
		fmt.Printf("reason only   : %v\n", errors.Unwrap(err)) // safe for 400 response
	}
}

func tempDir() (string, func()) {
	dir, err := os.MkdirTemp("", "authcore-email-example-*")
	if err != nil {
		log.Fatalf("create temp dir: %v", err)
	}
	return dir, func() { _ = os.RemoveAll(dir) }
}
