// Command probe is the binary the recipe script in this directory runs inside
// each authcore container replica. It mirrors the snippet from
// docs/guides/containers.md, with authcore's default logger left on: load keys from a
// pre-provisioned directory, fail closed when the set is missing, and report
// the key id so the recipe can assert that every replica saw the same keys.
//
// On success the process prints "key id <id>" to stdout and blocks until
// SIGINT or SIGTERM, so the recipe can poll its logs while the
// replicas stay up. The recipe tears them down with `podup down`, which sends
// SIGTERM; the signal handler then exits 0.
//
// With -check the process loads the keys the same way, prints nothing and
// exits at once, 0 when the set is complete and 1 when it is not. The compose
// file runs that as the container healthcheck, so "healthy" means the keys
// are still readable by the process that serves, not merely that a process
// exists.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/Glyndor/authcore"
)

func main() {
	check := flag.Bool("check", false, "load the keys, print nothing and exit (healthcheck)")
	flag.Parse()

	if code := load(os.Getenv("AUTHCORE_KEYS_DIR"), *check, os.Stdout, os.Stderr); code != 0 {
		os.Exit(code)
	}
	if *check {
		return
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
}

// load opens the keys under dir without ever writing: an incomplete directory
// is an error, never a reason to generate a new set. It prints the key id to
// stdout unless quiet is set, reports a failure on stderr, and returns the
// process exit code.
func load(dir string, quiet bool, stdout, stderr io.Writer) int {
	cfg := authcore.DefaultConfig()
	cfg.KeysDir = dir
	cfg.RequireExistingKeys = true
	if quiet {
		cfg.EnableLogs = false
	}
	auth, err := authcore.New(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "probe: %v\n", err)
		return 1
	}
	if !quiet {
		fmt.Fprintf(stdout, "key id %s\n", auth.Keys().KeyID())
	}
	return 0
}
