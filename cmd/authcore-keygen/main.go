// Command authcore-keygen writes a fresh authcore key set into a new directory
// so it can be mounted as a secret, copied into a volume, or uploaded to a
// secret manager.
//
// # Why it exists
//
// Config.RequireExistingKeys makes a deployment refuse to start unless the
// three key files (ed25519_private.pem, ed25519_public.pem, refresh_secret.key)
// are already in place. With this flag set, the library does not write the
// files on startup; the operator must produce them ahead of time. The library
// still writes them on first run when the flag is off, so it is the flag that
// turns the one-off generation into a refusal. authcore-keygen separates the
// two concerns: with this tool and Config.RequireExistingKeys, key generation
// happens once, here, and never inside the application, and the keys are
// produced by a small tool that only writes to a brand-new directory and never
// overwrites anything.
//
// # One-time workflow
//
//  1. install the tool:
//     go install github.com/Glyndor/authcore/cmd/authcore-keygen@latest
//  2. generate the key set once, on a host you trust:
//     authcore-keygen -out ./keys
//     # prints the absolute path of the new directory and the key id.
//  3. back the directory up before any deployment touches it; losing
//     refresh_secret.key is permanent (every stored refresh-token hash,
//     API-key hash and auth/field encrypted column depends on it).
//  4. ship it to the deployment:
//     - Podman / Kubernetes secret, one file per file; or
//     - a named volume mounted read-only at KeysDir on every replica.
//  5. start the application with Config.RequireExistingKeys = true. The
//     keys directory is loaded, never regenerated.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/Glyndor/authcore/internal/keymanager"
)

// usage is the multi-line usage banner written to stderr on a usage error.
// It is intentionally short; the package doc above is the longer story.
const usage = `usage: authcore-keygen -out PATH

Generates a fresh authcore key set (ed25519_private.pem, ed25519_public.pem,
refresh_secret.key, metadata.json) into a NEW directory at PATH. The directory
must not already exist: this tool never writes into an existing directory.

After generation, back the directory up and ship it to your deployment
(Podman secret, Kubernetes secret, or a read-only named volume). Start the
application with Config.RequireExistingKeys = true so it loads the keys
instead of regenerating them.

`

// exitUsage is the process exit code for a usage error (missing or malformed
// flag, an unexpected positional argument).
const exitUsage = 2

// exitFailure is the process exit code for a runtime error (the directory
// already existed, a write failed, the keymanager refused the directory).
const exitFailure = 1

// newDirMode is the mode applied to the new key directory. Owner-only access
// mirrors what keymanager.New applies on its own mkdir path, so the tool and
// the library agree on the directory mode.
const newDirMode = 0o700

// run is the entire body of the authcore-keygen command.
//
// args holds the arguments that would otherwise live in os.Args[1:].
// stdout receives the success line(s); stderr receives errors and warnings.
//
// It returns the process exit code: 0 on success, exitUsage on a usage
// error, exitFailure on a runtime error. main() calls os.Exit on the result.
//
// All key generation flows through keymanager.New, which writes the three
// key files transactionally (staging, hard-link publish, metadata) so the
// tool does not duplicate that logic.
func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("authcore-keygen", flag.ContinueOnError)
	flags.SetOutput(stderr)
	out := flags.String("out", "", "path of the new directory to create and write the key set into (must not exist)")

	if err := flags.Parse(args); err != nil {
		// flag has already printed the error to flags.Output() (stderr).
		if errors.Is(err, flag.ErrHelp) {
			return exitUsage
		}
		fmt.Fprint(stderr, usage)
		return exitUsage
	}

	if flags.NArg() != 0 {
		fmt.Fprintf(stderr, "authcore-keygen: unexpected positional argument(s): %s\n\n", flags.Args())
		fmt.Fprint(stderr, usage)
		return exitUsage
	}

	if *out == "" {
		fmt.Fprint(stderr, "authcore-keygen: -out is required\n\n")
		fmt.Fprint(stderr, usage)
		return exitUsage
	}

	absOut, err := filepath.Abs(*out)
	if err != nil {
		fmt.Fprintf(stderr, "authcore-keygen: cannot resolve %q: %v\n", *out, err)
		return exitFailure
	}

	// Create the new directory. Mkdir (not MkdirAll) so a missing parent is
	// the operator's error, not a silently-created tree.
	if err := os.Mkdir(absOut, newDirMode); err != nil {
		if errors.Is(err, fs.ErrExist) {
			fmt.Fprintf(stderr,
				"authcore-keygen: %s already exists; authcore-keygen never "+
					"writes into an existing directory. Pick a new path; an "+
					"existing directory may hold keys that are in use.\n",
				absOut)
			return exitFailure
		}
		fmt.Fprintf(stderr,
			"authcore-keygen: could not create directory %s: %v\n"+
				"the directory was NOT created; nothing was written.\n",
			absOut, err)
		return exitFailure
	}

	// keymanager.New reuses the existing transactional generator: staging
	// directory, hard-link publish, metadata, .gitignore. The logger it sees
	// keeps Info silent (the tool reports nothing at Info level) and forwards
	// Warn to stderr so a leftover staging directory or a read-only mount is
	// still surfaced to the operator.
	km, err := keymanager.New(absOut, stderrLogger{w: stderr})
	if err != nil {
		fmt.Fprintf(stderr,
			"authcore-keygen: key generation failed for %s: %v\n"+
				"the directory exists but is INCOMPLETE and must not be mounted "+
				"or used. Inspect it (it may hold a .staging-* worth keeping) "+
				"and remove it manually when you are sure.\n",
			absOut, err)
		return exitFailure
	}

	// Two lines, nothing else. Key material must never reach stdout or
	// stderr: a shell history, a CI log or a process trace would expose it.
	fmt.Fprintf(stdout, "wrote %s\n", absOut)
	fmt.Fprintf(stdout, "key id %s\n", km.KeyID())
	return 0
}

// stderrLogger satisfies keymanager's narrow logger interface: Info is
// discarded (the command has nothing to say at Info level), Warn is
// forwarded to the configured writer so a leftover staging directory or a
// read-only KeysDir is still visible to the operator.
type stderrLogger struct {
	w io.Writer
}

func (stderrLogger) Info(string, ...any) {}

func (l stderrLogger) Warn(msg string, args ...any) {
	fmt.Fprintf(l.w, "authcore-keygen: "+msg+"\n", args...)
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}
