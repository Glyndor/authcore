// Command apikey is a runnable example of authcore's opaque API key module:
// issue a key, then verify a presented key the way a request handler would.
package main

import (
	"fmt"
	"io"
	"log"
	"os"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/apikey"
)

func main() {
	if err := run(os.Stdout); err != nil {
		log.Fatal(err)
	}
}

// run is the whole example. It writes to w, so the tests read what a user would
// see, and returns an error where the demo used to exit.
func run(w io.Writer) error {
	auth, err := authcore.New(authcore.DefaultConfig())
	if err != nil {
		return fmt.Errorf("authcore: %w", err)
	}
	keyMod, err := apikey.New(auth)
	if err != nil {
		return fmt.Errorf("apikey: %w", err)
	}

	// Issue — show key.Key to the user exactly once; store key.ID and key.Hash.
	key, err := keyMod.Generate()
	if err != nil {
		return fmt.Errorf("generate: %w", err)
	}
	fmt.Fprintln(w, "Give to the user ONCE :", key.Key)
	fmt.Fprintln(w, "Store (lookup id)     :", key.ID)
	fmt.Fprintln(w, "Store (hash)          :", key.Hash)

	// Verify — what a request handler does: parse the id, fetch the stored hash
	// by id, then compare in constant time.
	id, err := keyMod.ParseID(key.Key)
	if err != nil {
		return fmt.Errorf("parse id: %w", err)
	}
	fmt.Fprintln(w, "\nIncoming request key parsed to id:", id)
	fmt.Fprintln(w, "Verify correct key  :", keyMod.Verify(key.Key, key.Hash))     // true
	fmt.Fprintln(w, "Verify tampered key :", keyMod.Verify(key.Key+"x", key.Hash)) // false

	// A malformed key is rejected before any lookup.
	if _, err := keyMod.ParseID("not-a-key"); err != nil {
		fmt.Fprintln(w, "Malformed key rejected:", err)
	}

	return nil
}
