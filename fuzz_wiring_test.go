package authcore_test

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEveryFuzzTargetIsWired asserts that every fuzz target in the tree is
// listed in the scheduled fuzz workflow.
//
// The two can drift apart without anything going red, because `go test` runs
// a fuzz target once over its seed corpus. A target that is missing from the
// workflow therefore still passes the suite, still reports as a test, and is
// never actually fuzzed: the 60s budget, the mutation and the persisted
// corpus all live in the scheduled job. Five targets had drifted out that way
// by v1.13.0, all of them in the three newest modules.
//
// This test fails on the pull request that adds an unwired target, which is
// the only moment the omission is cheap to fix.
func TestEveryFuzzTargetIsWired(t *testing.T) {
	inTree := fuzzTargetsInTree(t)
	inWorkflow := fuzzTargetsInWorkflow(t)

	for target := range inTree {
		if !inWorkflow[target] {
			t.Errorf("%s is not listed in .github/workflows/fuzz.yml, so it is never fuzzed", target)
		}
	}
	for target := range inWorkflow {
		if !inTree[target] {
			t.Errorf("%s is listed in .github/workflows/fuzz.yml but does not exist in the tree", target)
		}
	}
}

// fuzzTargetsInTree walks the repository for exported functions named Fuzz*
// that take a single *testing.F, and returns them as "./pkg.FuncName" keys.
func fuzzTargetsInTree(t *testing.T) map[string]bool {
	t.Helper()
	found := map[string]bool{}
	fset := token.NewFileSet()

	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// examples/ is a set of separate modules with their own go.mod,
			// and the fuzz job runs against this module only.
			if d.Name() == ".git" || d.Name() == "examples" || d.Name() == "testdata" {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		pkg := "./" + filepath.ToSlash(filepath.Dir(path))
		pkg = strings.TrimSuffix(pkg, "/.")
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || !strings.HasPrefix(fn.Name.Name, "Fuzz") {
				continue
			}
			if len(fn.Type.Params.List) != 1 {
				continue
			}
			star, ok := fn.Type.Params.List[0].Type.(*ast.StarExpr)
			if !ok {
				continue
			}
			sel, ok := star.X.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "F" {
				continue
			}
			found[pkg+"."+fn.Name.Name] = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the tree for fuzz targets: %v", err)
	}
	if len(found) == 0 {
		t.Fatal("found no fuzz targets in the tree, which means this test stopped measuring anything")
	}
	return found
}

// fuzzTargetsInWorkflow extracts the JSON array from the `targets:` block of
// the fuzz workflow. The block is a YAML folded scalar holding JSON, so the
// standard library is enough and no YAML dependency is needed.
func fuzzTargetsInWorkflow(t *testing.T) map[string]bool {
	t.Helper()
	const path = ".github/workflows/fuzz.yml"
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}

	_, rest, ok := strings.Cut(string(raw), "targets: >-")
	if !ok {
		t.Fatalf("%s no longer has a `targets: >-` block; this test cannot see what is wired", path)
	}
	start := strings.Index(rest, "[")
	end := strings.Index(rest, "]")
	if start < 0 || end < start {
		t.Fatalf("%s has a targets block with no JSON array in it", path)
	}

	var entries []struct {
		Package string `json:"package"`
		Func    string `json:"func"`
	}
	if err := json.Unmarshal([]byte(rest[start:end+1]), &entries); err != nil {
		t.Fatalf("parsing the targets array in %s: %v", path, err)
	}
	if len(entries) == 0 {
		t.Fatalf("%s lists no targets, which means the scheduled job fuzzes nothing", path)
	}

	wired := map[string]bool{}
	for _, e := range entries {
		wired[e.Package+"."+e.Func] = true
	}
	return wired
}
