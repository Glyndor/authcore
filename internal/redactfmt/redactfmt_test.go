package redactfmt_test

import (
	"fmt"
	"testing"

	"github.com/Glyndor/authcore/internal/redactfmt"
)

type sample struct{ secret string }

func (s sample) Format(f fmt.State, verb rune) { redactfmt.Format(f, verb, "pkg.Sample") }

func TestFormatRendersAFixedFormForEveryVerb(t *testing.T) {
	s := sample{secret: "hunter2-hunter2"}
	cases := map[string]string{
		"%v":  "pkg.Sample{redacted}",
		"%+v": "pkg.Sample{redacted}",
		"%s":  "pkg.Sample{redacted}",
		"%q":  `"pkg.Sample{redacted}"`,
		"%#v": "&pkg.Sample{redacted}",
		"%x":  "%!x(pkg.Sample)",
		"%d":  "%!d(pkg.Sample)",
	}
	for verb, want := range cases {
		if got := fmt.Sprintf(verb, s); got != want {
			t.Errorf("Sprintf(%q) = %q, want %q", verb, got, want)
		}
	}
}

func TestNilPointerAnswersForItself(t *testing.T) {
	if got := redactfmt.String(true, "pkg.Sample"); got != "<nil>" {
		t.Errorf("String(nil) = %q", got)
	}
	if got := redactfmt.GoString(true, "pkg.Sample"); got != "(*pkg.Sample)(nil)" {
		t.Errorf("GoString(nil) = %q", got)
	}
	if got := redactfmt.LogValue(true, "pkg.Sample").String(); got != "<nil>" {
		t.Errorf("LogValue(nil) = %q", got)
	}
	if got := redactfmt.LogValue(false, "pkg.Sample").String(); got != "pkg.Sample{redacted}" {
		t.Errorf("LogValue = %q", got)
	}
}

type detailed struct{}

func (detailed) Format(f fmt.State, verb rune) {
	redactfmt.FormatWith(f, verb, "pkg.Detailed", "short", "long")
}

func TestFormatWithUsesTheGivenForms(t *testing.T) {
	cases := map[string]string{"%v": "short", "%s": "short", "%q": `"short"`, "%#v": "long", "%d": "%!d(pkg.Detailed)"}
	for verb, want := range cases {
		if got := fmt.Sprintf(verb, detailed{}); got != want {
			t.Errorf("Sprintf(%q) = %q, want %q", verb, got, want)
		}
	}
}
