package candidate

import (
	"errors"
	"strings"
	"testing"
)

var errFetch = errors.New("oauth: cannot obtain provider signing keys")

func TestCandidateMatchesHonoursEveryRestriction(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		c    Candidate
		alg  string
		want bool
	}{
		{"unrestricted", Candidate{}, "RS256", true},
		{"alg pinned elsewhere", Candidate{Alg: "PS256"}, "RS256", false},
		{"encryption key", Candidate{Use: "enc"}, "RS256", false},
		{"verify not among key_ops", Candidate{KeyOps: map[string]struct{}{"encrypt": {}}}, "RS256", false},
		{"verify among key_ops", Candidate{KeyOps: map[string]struct{}{"verify": {}}}, "RS256", true},
	}
	for _, tc := range tests {
		if got := tc.c.Matches(tc.alg); got != tc.want {
			t.Errorf("%s: Matches(%q) = %v, want %v", tc.name, tc.alg, got, tc.want)
		}
	}
}

func TestPickCandidateNamesWhatFailed(t *testing.T) {
	t.Parallel()
	_, err := Pick(errFetch, nil, "", "RS256")
	if !errors.Is(err, errFetch) || !strings.Contains(err.Error(), "no candidate matches alg") {
		t.Fatalf("anonymous lookup: %v", err)
	}
	_, err = Pick(errFetch, nil, "k1", "RS256")
	if !errors.Is(err, errFetch) || !strings.Contains(err.Error(), `kid "k1"`) {
		t.Fatalf("named lookup: %v", err)
	}
}

// Pick skips a candidate the token's alg may not use and returns the first one
// it may, so two keys sharing a kid stay individually selectable.
func TestPickReturnsTheFirstCandidateTheAlgMayUse(t *testing.T) {
	t.Parallel()
	pinned := Candidate{Pub: "rsa", Alg: "RS256"}
	other := Candidate{Pub: "ec", Alg: "ES256"}

	got, err := Pick(errFetch, []Candidate{pinned, other}, "k1", "ES256")
	if err != nil || got.Pub != "ec" {
		t.Fatalf("Pick(ES256) = %+v, %v; want the EC candidate", got, err)
	}
	got, err = Pick(errFetch, []Candidate{pinned, other}, "k1", "RS256")
	if err != nil || got.Pub != "rsa" {
		t.Fatalf("Pick(RS256) = %+v, %v; want the RSA candidate", got, err)
	}
}
