package pkce

import (
	"encoding/base64"
	"errors"
	"testing"
)

// TestChallengeMatchesRFC7636 uses the verifier/challenge pair published in
// RFC 7636 appendix B.
func TestChallengeMatchesRFC7636(t *testing.T) {
	t.Parallel()
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	const want = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if got := Challenge(verifier); got != want {
		t.Fatalf("Challenge = %q, want %q", got, want)
	}
}

func TestRandomURLTokenReportsAnEntropyFailure(t *testing.T) {
	prev := readRandom
	t.Cleanup(func() { readRandom = prev })
	readRandom = func([]byte) (int, error) { return 0, errors.New("no entropy") }
	if tok, err := RandomURLToken(); err == nil || tok != "" {
		t.Fatalf("RandomURLToken = %q, %v; want an error and no token", tok, err)
	}
}

func TestRandomURLTokenIsUnpaddedAndUnique(t *testing.T) {
	t.Parallel()
	seen := map[string]bool{}
	for range 64 {
		tok, err := RandomURLToken()
		if err != nil {
			t.Fatalf("RandomURLToken: %v", err)
		}
		raw, err := base64.RawURLEncoding.DecodeString(tok)
		if err != nil {
			t.Fatalf("token %q is not unpadded base64url: %v", tok, err)
		}
		if len(raw) != randomTokenBytes {
			t.Fatalf("token carries %d bytes, want %d", len(raw), randomTokenBytes)
		}
		if seen[tok] {
			t.Fatalf("token %q repeated", tok)
		}
		seen[tok] = true
	}
}
