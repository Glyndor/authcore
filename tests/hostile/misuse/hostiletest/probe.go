package hostiletest

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// Panics runs fn and reports whether it panicked and with what.
func Panics(fn func()) (panicked bool, value any) {
	defer func() {
		if r := recover(); r != nil {
			panicked, value = true, r
		}
	}()
	fn()
	return false, nil
}

// NoPanic fails the test when fn panics. A misused value must answer with an
// error; a panic takes the caller's request goroutine, and often the process,
// down with it.
func NoPanic(t testing.TB, name string, fn func()) {
	t.Helper()
	if p, v := Panics(fn); p {
		t.Errorf("%s panicked: %v", name, v)
	}
}

// prefixLen is how many leading bytes of a secret a rendering must not show.
// Twelve random bytes make an accidental match in unrelated text negligible.
const prefixLen = 12

// Forms returns the spellings under which the first bytes of secret would show
// up in formatted output: fmt's decimal list, fmt's hex list, plain hex, and
// both base64 alphabets.
func Forms(secret []byte) []string {
	head := secret
	if len(head) > prefixLen {
		head = head[:prefixLen]
	}
	dec := make([]string, len(head))
	hexs := make([]string, len(head))
	for i, b := range head {
		dec[i] = fmt.Sprint(b)
		hexs[i] = fmt.Sprintf("0x%x", b)
	}
	forms := []string{
		strings.Join(dec, " "),
		strings.Join(hexs, ", "),
		hex.EncodeToString(head),
		clip(base64.StdEncoding.EncodeToString(head)),
		clip(base64.RawURLEncoding.EncodeToString(head)),
	}
	if utf8.Valid(head) && !strings.ContainsFunc(string(head), unicode.IsControl) {
		forms = append(forms, string(head))
	}
	return forms
}

// Leaks returns the forms of the secrets that appear in out.
func Leaks(out string, secrets ...[]byte) []string {
	var found []string
	for _, s := range secrets {
		for _, form := range Forms(s) {
			if strings.Contains(out, form) {
				found = append(found, form)
			}
		}
	}
	return found
}

// NoLeak fails the test when out shows any of the secrets in any spelling.
func NoLeak(t testing.TB, what, out string, secrets ...[]byte) {
	t.Helper()
	if found := Leaks(out, secrets...); len(found) > 0 {
		t.Errorf("%s shows secret material (%d spelling(s) found)", what, len(found))
	}
}

// clip keeps the first twelve characters of an encoding, so the match does not
// depend on how the bytes after the prefix were encoded.
func clip(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}
