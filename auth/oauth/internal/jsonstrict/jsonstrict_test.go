package jsonstrict_test

import (
	"testing"

	"github.com/Glyndor/authcore/auth/oauth/internal/jsonstrict"
)

// Once counts the writes of one member, so a document that spells it two ways
// is noticed.
func TestOnce_countsTheWrites(t *testing.T) {
	t.Parallel()
	var o jsonstrict.Once
	if o.Twice() {
		t.Error("a member nobody wrote was written twice")
	}
	if err := o.UnmarshalJSON([]byte(`"a"`)); err != nil {
		t.Fatal(err)
	}
	if o.Twice() {
		t.Error("a member written once was written twice")
	}
	if err := o.UnmarshalJSON([]byte(`"b"`)); err != nil {
		t.Fatal(err)
	}
	if !o.Twice() {
		t.Error("a member written twice was not written twice")
	}
}

// Text that encoding/json would repair is refused: a byte that is not valid
// UTF-8 and a surrogate escape that stands in no pair both become U+FFFD.
func TestWellFormedText_refusesRepairedText(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, in string
		want     bool
	}{
		{"ascii", `{"a":"b"}`, true},
		{"multi-byte utf-8", `{"a":"é😀"}`, true},
		{"an explicit replacement character", `{"a":"�"}`, true},
		{"a surrogate pair", `{"a":"😀"}`, true},
		{"a surrogate pair in upper case", `{"a":"\uD83D\uDE00"}`, true},
		{"a byte that is not utf-8", "{\"a\":\"\xff\"}", false},
		{"another byte that is not utf-8", "{\"a\":\"\xfe\"}", false},
		{"a lone high surrogate", `{"a":"\ud800"}`, false},
		{"another lone high surrogate", `{"a":"\ud801"}`, false},
		{"a lone low surrogate", `{"a":"\udc00"}`, false},
		{"an escape that is cut short", `{"a":"\ud80`, false},
		{"an escape that is not hex", `{"a":"\udzzz"}`, false},
		{"an escape that carries no code point", `{"a":"a\nb"}`, true},
		{"a trailing backslash", `{"a":"b\`, false},
		{"a high surrogate with nothing after it", `{"a":"\ud800`, false},
		{"a high surrogate followed by a plain escape", `{"a":"\ud800\n"}`, false},
		{"a high surrogate followed by another escape", `{"a":"\ud800\u0041"}`, false},
		{"a high surrogate followed by a low surrogate", `{"a":"\ud800\udc00"}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := jsonstrict.WellFormedText([]byte(tc.in)); got != tc.want {
				t.Errorf("WellFormedText(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
