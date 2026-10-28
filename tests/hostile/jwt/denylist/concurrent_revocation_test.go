package denylist

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/jwt"
	"github.com/Glyndor/authcore/tests/hostile/jwt/hostiletest"
)

// liveDenylist is a revocation store that is written while the module reads
// it: revoke returns only after the entry is visible to every later reader.
type liveDenylist struct {
	mu      sync.RWMutex
	revoked map[string]bool
}

func (d *liveDenylist) IsRevoked(_ context.Context, jti string) (bool, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.revoked[jti], nil
}

func (d *liveDenylist) revoke(jti string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.revoked == nil {
		d.revoked = map[string]bool{}
	}
	d.revoked[jti] = true
}

// session is one login under attack: several holders of the same refresh
// token race to rotate it while the application revokes the session.
type session struct {
	id      int
	target  bool // the application revokes this session
	mu      sync.Mutex
	pair    *jwt.TokenPair
	won     atomic.Int64  // rotations that won the swap
	revoked chan struct{} // closed once revoke has returned
}

func (s *session) current() *jwt.TokenPair {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pair
}

// swap replaces old by next while old is still the stored hash, the
// compare-and-swap the application owns.
func (s *session) swap(old, next *jwt.TokenPair) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pair.RefreshTokenHash != old.RefreshTokenHash {
		return false
	}
	s.won.Add(1)
	s.pair = next
	return true
}

func isClosed(c chan struct{}) bool {
	select {
	case <-c:
		return true
	default:
		return false
	}
}

// Attacker: a thief racing the owner on a stolen refresh token while the
// owner's logout revokes the session. Forbidden effect: any token of the
// session verifies, or rotates, after the revocation call has returned.
// Sessions that were never revoked keep working, so the refusals are the
// denylist's and not collateral damage.
func TestHostile_Denylist_revocationHoldsUnderConcurrentRotation(t *testing.T) {
	e := hostiletest.NewEnv(t)
	dl := &liveDenylist{}
	m := e.Module(t, jwt.Config{Denylist: dl})

	const sessions, holders = 8, 6
	all := make([]*session, sessions)
	for i := range all {
		p, err := m.CreateTokens(hostiletest.Subject, hostiletest.Extra{})
		if err != nil {
			t.Fatal(err)
		}
		all[i] = &session{id: i, target: i%2 == 0, pair: p, revoked: make(chan struct{})}
	}

	var control atomic.Int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for _, s := range all {
		for range holders {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				s.hold(t, m, &control)
			}()
		}
		if s.target {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				s.revokeMidRace(dl)
			}()
		}
	}
	close(start)
	wg.Wait()

	for _, s := range all {
		s.checkEnd(t, m)
	}
	if control.Load() == 0 {
		t.Fatal("control: no rotation of an unrevoked session succeeded")
	}
}

// hold is one holder of the session's refresh token. A revoked session is
// attacked until a few rounds after the revocation; a control session for a
// fixed number of rounds.
func (s *session) hold(t *testing.T, m *jwt.JWT[hostiletest.Extra], control *atomic.Int64) {
	const ahead, controlRounds = 3, 60
	for round, after := 0, 0; after < ahead && (s.target || round < controlRounds); round++ {
		if isClosed(s.revoked) {
			after++
		}
		cur := s.current()
		seenRevoked := isClosed(s.revoked)
		next, err := m.RotateTokens(cur.RefreshToken, hostiletest.Extra{})
		switch {
		case seenRevoked && !errors.Is(err, jwt.ErrTokenRevoked):
			t.Errorf("session %d rotated after its revocation returned: %v", s.id, err)
			return
		case err != nil && !errors.Is(err, jwt.ErrTokenRevoked):
			t.Errorf("session %d: %v", s.id, err)
			return
		case err != nil && !s.target:
			t.Errorf("session %d was never revoked and was refused: %v", s.id, err)
			return
		case err != nil:
			return
		}
		if !s.target {
			control.Add(1)
		}
		if s.swap(cur, next) {
			if _, err := m.VerifyAccessToken(next.AccessToken); err != nil && !errors.Is(err, jwt.ErrTokenRevoked) {
				t.Errorf("session %d: %v", s.id, err)
			}
		}
	}
}

// revokeMidRace revokes in the middle of the race, not before it begins.
func (s *session) revokeMidRace(dl *liveDenylist) {
	for deadline := time.Now().Add(30 * time.Second); s.won.Load() < 5 && time.Now().Before(deadline); {
		runtime.Gosched()
	}
	dl.revoke(s.current().SessionID)
	close(s.revoked)
}

// checkEnd holds the last pair of the session to its fate.
func (s *session) checkEnd(t *testing.T, m *jwt.JWT[hostiletest.Extra]) {
	if s.target && s.won.Load() < 5 {
		t.Errorf("control: session %d was revoked before the race began (%d rotations)", s.id, s.won.Load())
	}
	last := s.current()
	_, accessErr := m.VerifyAccessToken(last.AccessToken)
	_, rotateErr := m.RotateTokens(last.RefreshToken, hostiletest.Extra{})
	if s.target {
		if !errors.Is(accessErr, jwt.ErrTokenRevoked) || !errors.Is(rotateErr, jwt.ErrTokenRevoked) {
			t.Errorf("revoked session %d ends with access %v, rotate %v", s.id, accessErr, rotateErr)
		}
	} else if accessErr != nil || rotateErr != nil {
		t.Errorf("session %d was never revoked and ends with access %v, rotate %v", s.id, accessErr, rotateErr)
	}
}
