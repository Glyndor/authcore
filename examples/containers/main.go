// Command probe is the binary the recipe script in this directory runs inside
// each authcore container replica. It mirrors the snippet from
// docs/containers.md, with authcore's default logger left on: load keys from a
// pre-provisioned directory, fail closed when the set is missing, and report
// the key id so the recipe can assert that every replica saw the same keys.
//
// On success the process prints "key id <id>" to stdout and blocks until
// SIGINT or SIGTERM, so the recipe can poll its logs while the
// replicas stay up. The recipe tears them down with `podup down`, which sends
// SIGTERM; the signal handler then exits 0.
package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/Glyndor/authcore"
)

func main() {
	cfg := authcore.DefaultConfig()
	cfg.KeysDir = os.Getenv("AUTHCORE_KEYS_DIR")
	cfg.RequireExistingKeys = true
	auth, err := authcore.New(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "probe: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("key id %s\n", auth.Keys().KeyID())

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
}
