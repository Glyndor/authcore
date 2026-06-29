// Command apikey is a runnable example of authcore's opaque API key module:
// issue a key, then verify a presented key the way a request handler would.
package main

import (
	"fmt"
	"log"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/apikey"
)

func main() {
	auth, err := authcore.New(authcore.DefaultConfig())
	if err != nil {
		log.Fatalf("authcore: %v", err)
	}
	keyMod, err := apikey.New(auth)
	if err != nil {
		log.Fatalf("apikey: %v", err)
	}

	// Issue — show key.Key to the user exactly once; store key.ID and key.Hash.
	key, err := keyMod.Generate()
	if err != nil {
		log.Fatalf("generate: %v", err)
	}
	fmt.Println("Give to the user ONCE :", key.Key)
	fmt.Println("Store (lookup id)     :", key.ID)
	fmt.Println("Store (hash)          :", key.Hash)

	// Verify — what a request handler does: parse the id, fetch the stored hash
	// by id, then compare in constant time.
	id, err := keyMod.ParseID(key.Key)
	if err != nil {
		log.Fatalf("parse id: %v", err)
	}
	fmt.Println("\nIncoming request key parsed to id:", id)
	fmt.Println("Verify correct key  :", keyMod.Verify(key.Key, key.Hash))       // true
	fmt.Println("Verify tampered key :", keyMod.Verify(key.Key+"x", key.Hash))   // false

	// A malformed key is rejected before any lookup.
	if _, err := keyMod.ParseID("not-a-key"); err != nil {
		fmt.Println("Malformed key rejected:", err)
	}
}
