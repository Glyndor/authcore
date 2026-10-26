package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/username"
)

func newModule(t *testing.T) *username.Username {
	t.Helper()
	auth, err := authcore.New(authcore.Config{KeysDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	mod, err := username.New(auth)
	if err != nil {
		t.Fatal(err)
	}
	return mod
}

// TestRunShowsTheDocumentedFlow runs the example.
func TestRunShowsTheDocumentedFlow(t *testing.T) {
	var out bytes.Buffer
	if err := run(&out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`stored as  : "alice_dev99"`, "ErrInvalidUsername:", "reason only"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q", want)
		}
	}
}

// TestImpersonationAndInjectionAreRefused feeds names that look like another
// account, a route, or a control character. A username is shown to other
// users and often becomes a URL path, so anything accepted here is a name an
// attacker can wear.
func TestImpersonationAndInjectionAreRefused(t *testing.T) {
	mod := newModule(t)
	cases := map[string]string{
		"empty": "", "spaces": "   ", "reserved": "admin", "reserved upper": "ADMIN", "reserved padded": "  admin  ",
		"reserved root": "root", "reserved route": "login", "reserved api": "api", "reserved support": "support",
		"Cyrillic a in admin":      "\u0430dmin",
		"Cyrillic o in root":       "r\u043eot",
		"fullwidth admin":          "\uff41\uff44\uff4d\uff49\uff4e",
		"Greek omicron":            "r\u03bf\u03bft",
		"zero-width inside":        "ali\u200bce",
		"right-to-left override":   "ali\u202ece",
		"newline":                  "alice\nbob",
		"CRLF":                     "alice\r\nSet-Cookie: x=1",
		"NUL":                      "ali\x00ce",
		"path traversal":           "../admin",
		"slash":                    "alice/bob",
		"backslash":                `alice\bob`,
		"dot":                      "alice.bob.",
		"at sign":                  "alice@bob",
		"percent":                  "alice%2fbob",
		"HTML":                     "<script>alert(1)</script>",
		"SQL":                      "alice' OR '1'='1",
		"consecutive underscores":  "alice__bob",
		"leading hyphen":           "-alice",
		"too short":                "ab",
		"long":                     strings.Repeat("a", 65),
		"one megabyte":             strings.Repeat("a", 1<<20),
		"invalid UTF-8":            "ali\xffce",
		"emoji":                    "alice\U0001f600",
		"combining mark":           "alice\u0301",
		"leading and trailing sep": "_alice_",
	}
	for name, raw := range cases {
		got, err := mod.ValidateAndNormalize(raw)
		if err == nil {
			t.Errorf("%s: accepted as %q", name, got)
			continue
		}
		if !errors.Is(err, username.ErrInvalidUsername) || errors.Unwrap(err) == nil {
			t.Errorf("%s: error %v does not follow the ErrInvalidUsername pattern the example relies on", name, err)
		}
	}
}

// TestNormalizationIsCanonical checks that every spelling of a name maps to
// one stored form, and that the form is stable.
func TestNormalizationIsCanonical(t *testing.T) {
	mod := newModule(t)
	for _, spelling := range []string{"alice_dev99", "Alice_Dev99", "ALICE_DEV99", "  Alice_Dev99  ", "\talice_dev99\n"} {
		got, err := mod.ValidateAndNormalize(spelling)
		if err != nil || got != "alice_dev99" {
			t.Errorf("%q \u2192 %q %v, want alice_dev99", spelling, got, err)
		}
	}
	if again, err := mod.ValidateAndNormalize("alice_dev99"); err != nil || again != "alice_dev99" {
		t.Errorf("normalizing the stored form changed it: %q %v", again, err)
	}
}
