package jwsheader

import (
	"encoding/base64"
	"errors"
	"testing"
)

func token(header string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(header)) + ".e30.c2ln"
}

func TestRejectCritical(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		token string
		want  error
	}{
		{"no crit", token(`{"alg":"RS256"}`), nil},
		{"crit list", token(`{"alg":"RS256","crit":["x"]}`), ErrCritical},
		{"empty crit", token(`{"alg":"RS256","crit":[]}`), ErrCritical},
		{"null crit", token(`{"alg":"RS256","crit":null}`), ErrCritical},
		{"not base64", "!!!.e30.c2ln", nil},
		{"not json", token(`[1,2]`), nil},
		{"no dot", "abc", nil},
	} {
		if got := RejectCritical(tc.token); !errors.Is(got, tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}
