package authcore_test

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// sha1AllowedIn is the set of packages permitted to import crypto/sha1.
//
// auth/totp is on it because RFC 6238 defines TOTP over HMAC-SHA1 and every
// authenticator app implements that, so a module using anything else is one
// nobody can pair with. SHA-1 collision attacks do not carry to HMAC.
var sha1AllowedIn = map[string]string{
	"auth/totp": "RFC 6238 TOTP is HMAC-SHA1; collision attacks do not apply to HMAC",
}

// TestSHA1IsImportedOnlyWhereItIsJustified keeps the G505 exclusion in
// audit.yml from covering more than it was granted for.
//
// The exclusion exists because standalone gosec ignores the //nolint pragma on
// the import in auth/totp, so the finding cannot be silenced at the call site
// the way it is for the linter. Excluding the rule repository-wide is the only
// mechanism available, and a repository-wide exclusion with nothing watching it
// is a control that reads as present and permits everything. This is what
// watches it: a second package reaching for crypto/sha1 fails here, on its own
// pull request, and has to argue for itself in this map rather than inherit a
// justification written about TOTP.
func TestSHA1IsImportedOnlyWhereItIsJustified(t *testing.T) {
	fset := token.NewFileSet()
	seen := map[string]bool{}

	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// examples/ are separate modules and are not covered by the audit
			// workflow, which runs against this module.
			if d.Name() == ".git" || d.Name() == "examples" || d.Name() == "testdata" {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, imp := range file.Imports {
			target, err := strconv.Unquote(imp.Path.Value)
			if err != nil || target != "crypto/sha1" {
				continue
			}
			pkg := filepath.ToSlash(filepath.Dir(path))
			seen[pkg] = true
			if _, ok := sha1AllowedIn[pkg]; !ok {
				t.Errorf("%s imports crypto/sha1, which the G505 exclusion in "+
					"audit.yml silences repository-wide. Justify it in "+
					"sha1AllowedIn or use a different hash.", path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the tree: %v", err)
	}

	// The other direction: an allowance that no longer describes the tree is an
	// exclusion nobody is accountable for, so it should be removed along with
	// the G505 entry in audit.yml.
	for pkg := range sha1AllowedIn {
		if !seen[pkg] {
			t.Errorf("%s no longer imports crypto/sha1; drop it from sha1AllowedIn "+
				"and drop G505 from gosec-exclude in audit.yml", pkg)
		}
	}
}
