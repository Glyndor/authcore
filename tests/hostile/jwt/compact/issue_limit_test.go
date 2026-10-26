package compact

import (
	"errors"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/jwt"
	"github.com/Glyndor/authcore/tests/hostile/jwt/hostiletest"
)

// maxTokenLen is the ceiling the verifier applies to a compact token. Issuance
// applies the same one, so a pair the module hands out always verifies.
const maxTokenLen = 8192

// longestIssued searches for the padding at which issuance starts to refuse
// with ErrTokenOversized (the token grows with the padding) and returns the
// longest token chosen by pick that was still issued, one byte of padding
// before that.
func longestIssued(t *testing.T, issue func(pad int) (*jwt.TokenPair, error), pick func(*jwt.TokenPair) string) string {
	t.Helper()
	oversized := func(pad int) bool {
		_, err := issue(pad)
		if err != nil && !errors.Is(err, jwt.ErrTokenOversized) {
			t.Fatalf("padding %d: %v, want ErrTokenOversized", pad, err)
		}
		return err != nil
	}
	lo, hi := 1000, 9000 // lo is issued, hi is refused
	if oversized(lo) || !oversized(hi) {
		t.Fatalf("the limit is not between a padding of %d and %d", lo, hi)
	}
	for hi-lo > 1 {
		if mid := (lo + hi) / 2; oversized(mid) {
			hi = mid
		} else {
			lo = mid
		}
	}
	pair, err := issue(lo)
	if err != nil {
		t.Fatalf("padding %d: %v", lo, err)
	}
	return pick(pair)
}

// A token of exactly the maximum length is issued and then verifies; one byte
// more is refused at issuance. The padding rides in the application payload
// for the access token and in the issuer for the refresh token.
func TestHostile_CompactForm_issuanceStopsExactlyAtTheVerifierLimit(t *testing.T) {
	e := hostiletest.NewEnv(t)
	m := e.Module(t, jwt.Config{})

	access := longestIssued(t,
		func(pad int) (*jwt.TokenPair, error) {
			return m.CreateTokens(hostiletest.Subject, hostiletest.Extra{Role: strings.Repeat("a", pad)})
		},
		func(p *jwt.TokenPair) string { return p.AccessToken })
	if len(access) != maxTokenLen {
		t.Fatalf("longest access token issued = %d bytes, want %d", len(access), maxTokenLen)
	}
	if _, err := m.VerifyAccessToken(access); err != nil {
		t.Fatalf("access token of %d bytes issued but refused: %v", len(access), err)
	}

	refresh := longestIssued(t,
		func(pad int) (*jwt.TokenPair, error) {
			mod := e.Module(t, jwt.Config{Issuer: strings.Repeat("i", pad)})
			return mod.CreateTokens(hostiletest.Subject, hostiletest.Extra{})
		},
		func(p *jwt.TokenPair) string { return p.RefreshToken })
	if len(refresh) != maxTokenLen {
		t.Fatalf("longest refresh token issued = %d bytes, want %d", len(refresh), maxTokenLen)
	}
}
