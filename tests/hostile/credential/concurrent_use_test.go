package credential_test

import (
	"encoding/base64"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/credential"
)

// Class: one module shared by many goroutines (run with -race). The module is
// documented as safe for concurrent use; this uses it that way, mixing the
// operations, and checks every answer.

func TestHostile_Concurrent_issueAndVerifyOnOneModule(t *testing.T) {
	m := newModule(t)
	const goroutines, each = 16, 250
	type minted struct{ purpose, subject, token, hash string }
	results := make([][]minted, goroutines)

	var wg sync.WaitGroup
	for g := range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range each {
				purpose, subject := "reset", "user-"+string(rune('a'+g))+"-"+string(rune('a'+i%26))
				issued, err := m.Issue(purpose, subject)
				if err != nil {
					t.Error(err)
					return
				}
				results[g] = append(results[g], minted{purpose, subject, issued.Token, issued.Hash})
				if err := m.Verify(purpose, subject, issued.Token, issued.Hash, time.Now()); err != nil {
					t.Errorf("Verify of a fresh token: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()

	tokens, hashes := map[string]bool{}, map[string]bool{}
	for _, list := range results {
		for _, c := range list {
			if tokens[c.token] || hashes[c.hash] {
				t.Fatal("a token or hash repeated across goroutines")
			}
			tokens[c.token], hashes[c.hash] = true, true
		}
	}

	// Cross-verification, concurrently: every pairing other than a token's own
	// is refused and its own is accepted.
	flat := make([]minted, 0, goroutines*each)
	for _, list := range results {
		flat = append(flat, list...)
	}
	for g := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := g; i < len(flat); i += 8 {
				own, other := flat[i], flat[(i+1)%len(flat)]
				if err := m.Verify(own.purpose, own.subject, own.token, own.hash, time.Now()); err != nil {
					t.Errorf("own pairing refused: %v", err)
					return
				}
				if err := m.Verify(own.purpose, own.subject, own.token, other.hash, time.Now()); !errors.Is(err, credential.ErrInvalidCredential) {
					t.Errorf("another token's hash accepted: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
}

// The token is 32 bytes of CSPRNG output spelled in unpadded URL-safe base64.
// Over 10000 tokens every character position uses (nearly) the whole alphabet,
// the last character only its four live bits, and the decoded bytes are
// balanced. A counter, a time-seeded value or a short token fails here.
func TestHostile_Token_isUniformAcrossPositions(t *testing.T) {
	m := newModule(t)
	const n = 10000
	var perPos [43]map[byte]int
	for i := range perPos {
		perPos[i] = map[byte]int{}
	}
	var ones [256]int
	seen := map[string]bool{}
	for range n {
		issued, err := m.Issue("reset", "alice")
		if err != nil {
			t.Fatal(err)
		}
		if len(issued.Token) != 43 {
			t.Fatalf("token has %d characters, want 43", len(issued.Token))
		}
		if seen[issued.Token] {
			t.Fatal("a token repeated")
		}
		seen[issued.Token] = true
		for p := range 43 {
			perPos[p][issued.Token[p]]++
		}
		raw, err := base64.RawURLEncoding.DecodeString(issued.Token)
		if err != nil || len(raw) != 32 {
			t.Fatalf("token does not decode to 32 bytes: %d, %v", len(raw), err)
		}
		for i, b := range raw {
			for bit := range 8 {
				if b&(1<<bit) != 0 {
					ones[i*8+bit]++
				}
			}
		}
	}
	for p, seenChars := range perPos {
		want := 62
		if p == 42 {
			want = 15 // the last character carries four bits
		}
		if len(seenChars) < want {
			t.Errorf("token position %d used only %d distinct characters in %d tokens", p, len(seenChars), n)
		}
	}
	for i, c := range ones {
		if frac := float64(c) / n; frac < 0.46 || frac > 0.54 {
			t.Errorf("token bit %d is set in %.1f%% of tokens", i, frac*100)
		}
	}
}
