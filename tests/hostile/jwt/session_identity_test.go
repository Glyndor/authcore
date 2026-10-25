package jwt_test

import (
	"sync"
	"testing"

	"github.com/Glyndor/authcore/auth/jwt"
)

// Many goroutines issue tokens at once, as a login spike does. Every session
// id (the jti the denylist is keyed by) must be unique, every refresh token
// must be unique, and every pair must verify. Two sessions sharing a jti would
// share a revocation entry: revoking one would log out the other.
func TestHostile_SessionIdentity_jtiIsUniqueUnderConcurrentIssuing(t *testing.T) {
	e := newEnv(t)
	m := e.module(t, jwt.Config{})
	const workers, perWorker = 24, 150

	type issued struct{ jti, refresh, hash string }
	out := make([][]issued, workers)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				p, err := m.CreateTokens(subject, extra{})
				if err != nil {
					t.Errorf("CreateTokens: %v", err)
					return
				}
				c, err := m.VerifyAccessToken(p.AccessToken)
				if err != nil || c.TokenID != p.SessionID {
					t.Errorf("a freshly issued token fails verification: %v", err)
					return
				}
				out[w] = append(out[w], issued{p.SessionID, p.RefreshToken, p.RefreshTokenHash})
			}
		}()
	}
	wg.Wait()

	jtis, refreshes, hashes := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, batch := range out {
		for _, s := range batch {
			if jtis[s.jti] {
				t.Fatalf("session id %s was issued twice", s.jti)
			}
			if refreshes[s.refresh] || hashes[s.hash] {
				t.Fatal("two sessions share a refresh token or its hash")
			}
			jtis[s.jti], refreshes[s.refresh], hashes[s.hash] = true, true, true
		}
	}
	if len(jtis) != workers*perWorker {
		t.Fatalf("issued %d distinct sessions, want %d", len(jtis), workers*perWorker)
	}
}

// Rotating one session many times, from many goroutines, keeps the jti and
// never repeats a refresh token: the app's compare-and-swap on the hash relies
// on every rotation producing a hash nobody has stored before.
func TestHostile_SessionIdentity_rotationsKeepTheJTIAndNeverRepeatATokenUnderLoad(t *testing.T) {
	e := newEnv(t)
	m := e.module(t, jwt.Config{})
	first, err := m.CreateTokens(subject, extra{})
	if err != nil {
		t.Fatal(err)
	}

	const workers, perWorker = 16, 100
	var (
		mu     sync.Mutex
		hashes = map[string]bool{first.RefreshTokenHash: true}
		wg     sync.WaitGroup
	)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				p, err := m.RotateTokens(first.RefreshToken, extra{Role: "r"})
				if err != nil {
					t.Errorf("RotateTokens: %v", err)
					return
				}
				if p.SessionID != first.SessionID {
					t.Errorf("rotation changed the session id: %s -> %s", first.SessionID, p.SessionID)
					return
				}
				mu.Lock()
				dup := hashes[p.RefreshTokenHash]
				hashes[p.RefreshTokenHash] = true
				mu.Unlock()
				if dup {
					t.Error("two rotations produced the same refresh token hash")
					return
				}
			}
		}()
	}
	wg.Wait()
	if len(hashes) != 1+workers*perWorker {
		t.Fatalf("%d distinct hashes, want %d", len(hashes), 1+workers*perWorker)
	}
}
