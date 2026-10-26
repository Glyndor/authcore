// Command email demonstrates the auth/email module: validating, normalizing,
// and optionally verifying that an email domain can receive messages via DNS MX lookup.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/email"
)

func main() {
	if err := run(os.Stdout, true); err != nil {
		log.Fatal(err)
	}
}

// run is the whole example. It writes to w, so the tests read what a user would
// see, and returns an error where the demo used to exit.
func run(w io.Writer, checkDNS bool) error {
	// -------------------------------------------------------------------------
	// Setup: initialise authcore and the email module.
	// Close() stops the background cache eviction goroutine — always defer it.
	// -------------------------------------------------------------------------
	dir, cleanup := tempDir()
	defer cleanup()

	auth, err := authcore.New(authcore.Config{KeysDir: dir})
	if err != nil {
		return fmt.Errorf("authcore: %w", err)
	}

	emailMod, err := email.New(auth)
	if err != nil {
		return fmt.Errorf("email module: %w", err)
	}
	defer emailMod.Close()

	// -------------------------------------------------------------------------
	// Example 1: ValidateAndNormalize — the single entry point.
	// It lowercases, trims whitespace, and validates in one atomic step.
	// The returned string is the canonical form — always store and query this.
	// -------------------------------------------------------------------------
	fmt.Fprintln(w, "=== ValidateAndNormalize ===")

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
			fmt.Fprintf(w, "rejected  %q → %s\n", raw, errors.Unwrap(err).Error())
		} else {
			fmt.Fprintf(w, "accepted  %q → %q\n", raw, normalized)
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
	fmt.Fprintln(w, "\n=== VerifyDomain ===")

	if checkDNS {
		normalized, _ := emailMod.ValidateAndNormalize("user@gmail.com")

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		err = emailMod.VerifyDomain(ctx, normalized)
		switch {
		case err == nil:
			fmt.Fprintf(w, "domain OK     : %s\n", normalized)
		case errors.Is(err, email.ErrDomainNoMX):
			// Domain exists but cannot receive email — safe to tell the user.
			fmt.Fprintf(w, "no MX records : %s\n", normalized)
		case errors.Is(err, email.ErrDomainUnresolvable):
			// DNS lookup failed — do NOT block the user, log and continue.
			fmt.Fprintf(w, "DNS unavailable (soft failure): %v\n", err)
		}
	} else {
		fmt.Fprintln(w, "skipped: DNS checks are off")
	}

	// -------------------------------------------------------------------------
	// Example 3: error handling — ErrInvalidEmail wraps the specific reason.
	// -------------------------------------------------------------------------
	fmt.Fprintln(w, "\n=== Error handling ===")

	_, err = emailMod.ValidateAndNormalize("bad@@email")
	if errors.Is(err, email.ErrInvalidEmail) {
		fmt.Fprintf(w, "ErrInvalidEmail: %v\n", err)
		fmt.Fprintf(w, "reason only   : %v\n", errors.Unwrap(err)) // safe for 400 response
	}

	return nil
}

func tempDir() (string, func()) {
	dir, err := os.MkdirTemp("", "authcore-email-example-*")
	if err != nil {
		log.Fatalf("create temp dir: %v", err)
	}
	return dir, func() { _ = os.RemoveAll(dir) }
}
