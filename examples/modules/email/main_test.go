package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/email"
)

func newModule(t *testing.T) *email.Email {
	t.Helper()
	auth, err := authcore.New(authcore.Config{KeysDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	mod, err := email.New(auth)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mod.Close)
	return mod
}

// TestRunWithoutTheNetwork runs the example with the DNS step off, which is
// the part that would reach a resolver.
func TestRunWithoutTheNetwork(t *testing.T) {
	var out bytes.Buffer
	if err := run(&out, false); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"accepted  \"  USER@EXAMPLE.COM  \" \u2192 \"user@example.com\"", "rejected", "skipped: DNS checks are off", "ErrInvalidEmail:"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q", want)
		}
	}
	if strings.Contains(out.String(), "domain OK") || strings.Contains(out.String(), "DNS unavailable") {
		t.Error("the DNS step ran with checkDNS off")
	}
}

// TestHostileAddressesAreRefused feeds the addresses used for header
// injection, parser confusion and resource abuse. The example stores the
// normalized form, so anything accepted here is stored and mailed to.
func TestHostileAddressesAreRefused(t *testing.T) {
	mod := newModule(t)
	long := strings.Repeat("a", 65)
	cases := map[string]string{
		"empty": "", "spaces only": "   ", "no at sign": "notanemail", "two at signs": "bad@@email",
		"no dot in domain": "user@localhost", "double dot": "user@example..com", "leading dot": "user@.example.com",
		"CRLF Bcc injection":   "user@example.com\r\nBcc: victim@example.com",
		"LF injection":         "user@example.com\nBcc: victim@example.com",
		"newline in local":     "us\ner@example.com",
		"NUL byte":             "user\x00@example.com",
		"space inside":         "us er@example.com",
		"angle brackets":       "<user@example.com>",
		"display name":         "Ana <user@example.com>",
		"comma list":           "a@example.com,b@example.com",
		"semicolon list":       "a@example.com;b@example.com",
		"quoted local":         `"a b"@example.com`,
		"long local part":      long + "@example.com",
		"long domain label":    "user@" + strings.Repeat("a", 64) + ".com",
		"very long":            strings.Repeat("a", 300) + "@example.com",
		"one megabyte":         strings.Repeat("a", 1<<20) + "@example.com",
		"IP literal":           "user@[127.0.0.1]",
		"trailing dot":         "user@example.com.",
		"invalid UTF-8":        "us\xffer@example.com",
		"zero-width in local":  "us\u200ber@example.com",
		"right-to-left switch": "user@exam\u202eple.com",
	}
	for name, raw := range cases {
		got, err := mod.ValidateAndNormalize(raw)
		if err == nil {
			t.Errorf("%s: accepted as %q", name, got)
			continue
		}
		if !errors.Is(err, email.ErrInvalidEmail) || errors.Unwrap(err) == nil {
			t.Errorf("%s: error %v does not follow the ErrInvalidEmail pattern the example relies on", name, err)
		}
		if got != "" {
			t.Errorf("%s: returned %q with an error", name, got)
		}
	}
}

// TestNormalizationIsCanonical checks the property the example states: the
// result is the form to store and to query, so it must be stable and equal
// for every spelling of one address.
func TestNormalizationIsCanonical(t *testing.T) {
	mod := newModule(t)
	spellings := []string{"user@example.com", "USER@EXAMPLE.COM", "  User@Example.Com  ", "\tuser@example.com\n"}

	first, err := mod.ValidateAndNormalize(spellings[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range spellings {
		got, err := mod.ValidateAndNormalize(s)
		if err != nil || got != first {
			t.Errorf("%q \u2192 %q %v, want %q", s, got, err, first)
		}
	}
	again, err := mod.ValidateAndNormalize(first)
	if err != nil || again != first {
		t.Errorf("normalizing the normalized form changed it: %q \u2192 %q", first, again)
	}
}
