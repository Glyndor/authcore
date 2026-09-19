package authcore_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// scopeDenials are the phrases the docs use to tell a reader that something is
// their job rather than the library's.
var scopeDenials = []string{
	"does not include",
	"not part of authcore",
	"authcore does not",
	"you provide or skip",
	"build on top",
}

// TestDocsDoNotDisownAShippedModule fails when a bullet in the documentation
// denies that authcore covers something and names a module that ships.
//
// This existed as a real defect: section 8 of docs/secure-login.md listed
// "MFA / TOTP" as out of scope for two releases after auth/totp shipped, so
// the recipe page sent readers to hand roll a module sitting audited in the
// same tree. A stale feature list is silent; a sentence like that makes a
// positive claim that the module does not exist.
//
// Where this stops working, stated rather than discovered later: it matches
// the directory name. The same bullet also disowned "password-reset flows and
// email verification", which is auth/credential under a description rather
// than a name, and no name match catches that. This test would have caught one
// of the two instances. Do not read a green run as proof the docs describe the
// current module set.
func TestDocsDoNotDisownAShippedModule(t *testing.T) {
	modules := shippedModules(t)

	files, err := filepath.Glob("docs/*.md")
	if err != nil {
		t.Fatalf("globbing docs: %v", err)
	}
	files = append(files, "README.md")

	for _, path := range files {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		for _, block := range bulletBlocks(string(raw)) {
			lower := strings.ToLower(block.text)
			if !containsAny(lower, scopeDenials) {
				continue
			}
			for _, module := range modules {
				if mentionsModule(lower, module) {
					t.Errorf("%s:%d says authcore does not cover %q, but auth/%s ships:\n\t%s",
						path, block.line, module, module, strings.ReplaceAll(block.text, "\n", "\n\t"))
				}
			}
		}
	}
}

// shippedModules lists the directory names under auth/.
func shippedModules(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir("auth")
	if err != nil {
		t.Fatalf("reading auth/: %v", err)
	}
	var modules []string
	for _, e := range entries {
		if e.IsDir() {
			modules = append(modules, strings.ToLower(e.Name()))
		}
	}
	if len(modules) == 0 {
		t.Fatal("found no modules under auth/, which means this test stopped measuring anything")
	}
	return modules
}

type bulletBlock struct {
	line int
	text string
}

// bulletBlocks groups each markdown bullet with its wrapped continuation
// lines. The defect this test guards against had the module name on the first
// line of a bullet and the denial on the second, so neither a line-by-line nor
// a paragraph-wide scan sees it as one statement.
func bulletBlocks(content string) []bulletBlock {
	var blocks []bulletBlock
	var current *bulletBlock

	flush := func() {
		if current != nil {
			blocks = append(blocks, *current)
			current = nil
		}
	}

	for i, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimLeft(line, " \t")
		isBullet := strings.HasPrefix(trimmed, "- ") || strings.HasPrefix(trimmed, "* ")
		isContinuation := current != nil && line != trimmed && trimmed != ""

		switch {
		case isBullet:
			flush()
			current = &bulletBlock{line: i + 1, text: trimmed}
		case isContinuation:
			current.text += "\n" + trimmed
		default:
			flush()
		}
	}
	flush()
	return blocks
}

// mentionsModule reports whether text names the module as its own token.
//
// A plain substring match is too loose here and said so on its first run:
// "Breached-password rejection is intentionally not part of authcore" is a
// true statement about a feature auth/password deliberately lacks (#133,
// #118), and a substring match read it as a denial that auth/password exists.
// A hyphen or a letter on either side means the word is part of a compound,
// not a reference to the module. A slash is a boundary rather than a word
// byte, so a docs line naming auth/totp still matches.
func mentionsModule(text, module string) bool {
	for offset := 0; ; {
		i := strings.Index(text[offset:], module)
		if i < 0 {
			return false
		}
		start := offset + i
		end := start + len(module)
		if !isWordByte(text, start-1) && !isWordByte(text, end) {
			return true
		}
		offset = start + 1
	}
}

// isWordByte reports whether the byte at i continues a word. Out of range
// counts as a boundary.
func isWordByte(text string, i int) bool {
	if i < 0 || i >= len(text) {
		return false
	}
	c := text[i]
	return c == '-' || c == '_' ||
		(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

func containsAny(haystack string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(haystack, n) {
			return true
		}
	}
	return false
}
