package redact_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/redact"
)

// subject is a stand-in for the facade type: its only job is to hand fmt
// the same Formatter contract the facade implements.
type subject struct{}

func (subject) String() string   { return redact.Describe(false, "/tmp/keys", "kid") }
func (subject) GoString() string { return redact.Describe(true, "/tmp/keys", "kid") }

func (s subject) Format(f fmt.State, verb rune) {
	redact.Format(f, verb, s.String, s.GoString)
}

func TestDescribeNamesTheSafeFieldsAndRedactsTheRest(t *testing.T) {
	plain := redact.Describe(false, "/tmp/keys", "kid")
	goSyntax := redact.Describe(true, "/tmp/keys", "kid")

	if !strings.HasPrefix(plain, "keymanager.KeyManager{") || !strings.HasPrefix(goSyntax, "&keymanager.KeyManager{") {
		t.Fatalf("unexpected prefixes: %q, %q", plain, goSyntax)
	}
	for _, got := range []string{plain, goSyntax} {
		for _, want := range []string{`dir:"/tmp/keys"`, `keyID:"kid"`,
			"privateKey:" + redact.Placeholder,
			"publicKey:" + redact.Placeholder,
			"refreshSecret:" + redact.Placeholder} {
			if !strings.Contains(got, want) {
				t.Errorf("%q does not contain %q", got, want)
			}
		}
	}
}

func TestFormatPicksTheDescriptionForEachVerb(t *testing.T) {
	s := subject{}
	plain, goSyntax := s.String(), s.GoString()
	for format, want := range map[string]string{
		"%v":  plain,
		"%+v": plain,
		"%s":  plain,
		"%q":  fmt.Sprintf("%q", plain),
		"%#v": goSyntax,
	} {
		if got := fmt.Sprintf(format, s); got != want {
			t.Errorf("Sprintf(%q) = %q, want %q", format, got, want)
		}
	}
}

func TestFormatRefusesVerbsThatWouldFallBackToReflection(t *testing.T) {
	for _, verb := range []string{"%d", "%x", "%X", "%b"} {
		got := fmt.Sprintf(verb, subject{})
		if !strings.HasPrefix(got, "%!") || !strings.Contains(got, "(keymanager.KeyManager)") {
			t.Errorf("Sprintf(%q) = %q, want a %%!verb error", verb, got)
		}
	}
}
