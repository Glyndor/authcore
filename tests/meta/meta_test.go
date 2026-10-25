// Package meta_test holds the tests that read the repository itself rather
// than run its code: the docs, the fuzz workflow and the import graph.
// `go test ./...` runs them like any other package.
package meta_test

import (
	"fmt"
	"os"
	"testing"
)

// TestMain moves to the repository root so every test in this package can
// keep addressing docs/, .github/ and auth/ by their root-relative paths.
func TestMain(m *testing.M) {
	if err := os.Chdir("../.."); err != nil {
		fmt.Fprintln(os.Stderr, "meta: cannot move to the repository root:", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}
