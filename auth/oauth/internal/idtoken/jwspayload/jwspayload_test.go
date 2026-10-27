package jwspayload

import (
	"encoding/base64"
	"errors"
	"testing"
)

func token(payload string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`)) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".c2ln"
}

// The text of a payload is the text the signer wrote: a byte that is not
// valid UTF-8 and a surrogate escape that stands in no pair both become
// U+FFFD when the payload is read, and the identity the payload names is
// read from that text.
func TestCheckText(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, token string
		want        error
	}{
		{"plain payload", token(`{"sub":"user-abc"}`), nil},
		{"a payload with an emoji", token(`{"sub":"user-😀"}`), nil},
		{"a payload with an explicit replacement character", token(`{"sub":"user-�"}`), nil},
		{"a byte that is not utf-8", token("{\"sub\":\"user-\xff\"}"), ErrText},
		{"a lone high surrogate", token(`{"sub":"user-\ud800"}`), ErrText},
		{"a lone low surrogate", token(`{"sub":"user-\udc00"}`), ErrText},
		{"not base64", "!!!.e30.c2ln", nil},
		{"a payload that is not base64", "e30.!!!.c2ln", nil},
		{"no dot", "abc", nil},
		{"one dot", "abc.def", nil},
	} {
		if got := CheckText(tc.token); !errors.Is(got, tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}
