// Package denylist attacks revocation: a revoked session or token must stay
// dead on every path and the denylist must fail closed.
package denylist

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/jwt"
	"github.com/Glyndor/authcore/tests/hostile/jwt/hostiletest"
)

// stubDenylist is a revocation store the test controls: it can revoke, fail,
// stall until its context ends, and it records what it was asked.
type stubDenylist struct {
	mu       sync.Mutex
	revoked  map[string]bool
	err      error
	stall    bool
	calls    atomic.Int64
	seen     []string
	deadline time.Time
	hasDL    bool
}

func (d *stubDenylist) IsRevoked(ctx context.Context, jti string) (bool, error) {
	d.calls.Add(1)
	d.mu.Lock()
	d.seen = append(d.seen, jti)
	d.deadline, d.hasDL = ctx.Deadline()
	revoked, err, stall := d.revoked[jti], d.err, d.stall
	d.mu.Unlock()
	if stall {
		<-ctx.Done()
		return false, ctx.Err()
	}
	return revoked, err
}

func (d *stubDenylist) revoke(jti string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.revoked == nil {
		d.revoked = map[string]bool{}
	}
	d.revoked[jti] = true
}

// A revoked session id kills the access token and the refresh token of that
// session, and the pair a rotation would have produced.
func TestHostile_Denylist_revokedSessionIsDeadOnEveryPath(t *testing.T) {
	e := hostiletest.NewEnv(t)
	dl := &stubDenylist{}
	m := e.Module(t, jwt.Config{Denylist: dl})
	pair, err := m.CreateTokens(hostiletest.Subject, hostiletest.Extra{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.VerifyAccessToken(pair.AccessToken); err != nil {
		t.Fatalf("control: live session refused: %v", err)
	}

	dl.revoke(pair.SessionID)

	if c, err := m.VerifyAccessToken(pair.AccessToken); c != nil || !errors.Is(err, jwt.ErrTokenRevoked) {
		t.Fatalf("revoked access token = %+v, %v; want ErrTokenRevoked", c, err)
	}
	if p, err := m.RotateTokens(pair.RefreshToken, hostiletest.Extra{}); p != nil || !errors.Is(err, jwt.ErrTokenRevoked) {
		t.Fatalf("revoked refresh token = %+v, %v; want ErrTokenRevoked", p, err)
	}
}

// The denylist is the only revocation channel, so a denylist that cannot
// answer must not become "not revoked": a backend error, a stall that outlasts
// the caller's deadline, and an already-cancelled context all end in a refusal.
func TestHostile_Denylist_failsClosed(t *testing.T) {
	e := hostiletest.NewEnv(t)
	backendDown := errors.New("redis: connection refused")

	t.Run("backend error", func(t *testing.T) {
		m := e.Module(t, jwt.Config{Denylist: &stubDenylist{err: backendDown}})
		pair, err := e.Module(t, jwt.Config{}).CreateTokens(hostiletest.Subject, hostiletest.Extra{})
		if err != nil {
			t.Fatal(err)
		}
		c, err := m.VerifyAccessToken(pair.AccessToken)
		if c != nil || !errors.Is(err, backendDown) {
			t.Fatalf("VerifyAccessToken = %+v, %v; want the backend error and no claims", c, err)
		}
		if errors.Is(err, jwt.ErrTokenRevoked) {
			t.Fatal("a backend failure was reported as a revocation")
		}
		if p, err := m.RotateTokens(pair.RefreshToken, hostiletest.Extra{}); p != nil || !errors.Is(err, backendDown) {
			t.Fatalf("RotateTokens = %+v, %v; want the backend error and no pair", p, err)
		}
	})

	t.Run("backend error alongside a not-revoked answer", func(t *testing.T) {
		// A store that returns (false, err) must not be read as "false".
		m := e.Module(t, jwt.Config{Denylist: &stubDenylist{err: backendDown, revoked: map[string]bool{}}})
		pair, _ := e.Module(t, jwt.Config{}).CreateTokens(hostiletest.Subject, hostiletest.Extra{})
		if c, err := m.VerifyAccessToken(pair.AccessToken); c != nil || !errors.Is(err, backendDown) {
			t.Fatalf("VerifyAccessToken = %+v, %v; want the backend error and no claims", c, err)
		}
	})

	t.Run("stall outlasts the deadline", func(t *testing.T) {
		dl := &stubDenylist{stall: true}
		m := e.Module(t, jwt.Config{Denylist: dl})
		pair, _ := e.Module(t, jwt.Config{}).CreateTokens(hostiletest.Subject, hostiletest.Extra{})
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
		defer cancel()
		start := time.Now()
		c, err := m.VerifyAccessTokenContext(ctx, pair.AccessToken)
		if c != nil || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("VerifyAccessTokenContext = %+v, %v; want context.DeadlineExceeded", c, err)
		}
		if d := time.Since(start); d > 2*time.Second {
			t.Fatalf("returned after %v, the deadline was 30ms", d)
		}
		if p, err := m.RotateTokensContext(ctx, pair.RefreshToken, hostiletest.Extra{}); p != nil || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("RotateTokensContext under an expired deadline = %+v, %v; want context.DeadlineExceeded", p, err)
		}
	})

	t.Run("cancelled context", func(t *testing.T) {
		dl := &stubDenylist{stall: true}
		m := e.Module(t, jwt.Config{Denylist: dl})
		pair, _ := e.Module(t, jwt.Config{}).CreateTokens(hostiletest.Subject, hostiletest.Extra{})
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if c, err := m.VerifyAccessTokenContext(ctx, pair.AccessToken); c != nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("VerifyAccessTokenContext = %+v, %v; want context.Canceled", c, err)
		}
	})
}

// The context-less methods bound the revocation lookup themselves, so a stalled
// store cannot hold a request goroutine forever.
func TestHostile_Denylist_contextlessMethodsCarryADeadline(t *testing.T) {
	e := hostiletest.NewEnv(t)
	dl := &stubDenylist{}
	m := e.Module(t, jwt.Config{Denylist: dl})
	pair, _ := m.CreateTokens(hostiletest.Subject, hostiletest.Extra{})

	before := time.Now()
	if _, err := m.VerifyAccessToken(pair.AccessToken); err != nil {
		t.Fatal(err)
	}
	if !dl.hasDL {
		t.Fatal("VerifyAccessToken passed the denylist a context with no deadline")
	}
	if limit := before.Add(5*time.Second + time.Second); dl.deadline.After(limit) {
		t.Fatalf("deadline %v is more than the documented 5s ahead", dl.deadline.Sub(before))
	}

	dl.hasDL = false
	if _, err := m.RotateTokens(pair.RefreshToken, hostiletest.Extra{}); err != nil {
		t.Fatal(err)
	}
	if !dl.hasDL {
		t.Fatal("RotateTokens passed the denylist a context with no deadline")
	}
}

// A token that does not verify never reaches the denylist. If it did, anyone
// could turn the revocation backend into an amplifier by sending garbage with
// a chosen jti.
func TestHostile_Denylist_isNotQueriedForTokensThatFailEarlier(t *testing.T) {
	e := hostiletest.NewEnv(t)
	attacker := hostiletest.NewEnv(t)
	dl := &stubDenylist{}
	m := e.Module(t, jwt.Config{Denylist: dl})
	pair, _ := m.CreateTokens(hostiletest.Subject, hostiletest.Extra{})
	dl.calls.Store(0)

	hostile := []struct {
		token string
		want  error
	}{
		{"", jwt.ErrTokenMalformed},
		{"not-a-token", jwt.ErrTokenMalformed},
		{e.SignEdDSA(t, nil, hostiletest.With(hostiletest.ClaimsFor("access"), "exp", 1)), jwt.ErrTokenExpired},
		{attacker.SignEdDSA(t, map[string]any{"kid": e.Kid}, hostiletest.ClaimsFor("access")), jwt.ErrTokenInvalid},
		{e.SignEdDSA(t, nil, hostiletest.With(hostiletest.ClaimsFor("access"), "aud", "https://other.example")), jwt.ErrTokenInvalid},
		{pair.RefreshToken, jwt.ErrWrongTokenType}, // right signature, wrong kind for VerifyAccessToken
	}
	for _, h := range hostile {
		if _, err := m.VerifyAccessToken(h.token); !errors.Is(err, h.want) {
			t.Fatalf("hostile token %.40q: got %v, want %v", h.token, err, h.want)
		}
	}
	if n := dl.calls.Load(); n != 0 {
		t.Fatalf("the denylist was queried %d times for tokens that fail before it", n)
	}
}

// Replay: nothing in a token stops a second presentation, so the store is
// what makes a session single-use. After the store revokes the jti, a replay
// of a captured token is refused no matter how many times it is sent, and the
// store sees the jti the token carries, not one the adversary chose elsewhere.
func TestHostile_Replay_revokedJTIStaysRefusedUnderRepetition(t *testing.T) {
	e := hostiletest.NewEnv(t)
	dl := &stubDenylist{}
	m := e.Module(t, jwt.Config{Denylist: dl})
	pair, _ := m.CreateTokens(hostiletest.Subject, hostiletest.Extra{})
	dl.revoke(pair.SessionID)
	for i := 0; i < 200; i++ {
		if _, err := m.VerifyAccessToken(pair.AccessToken); !errors.Is(err, jwt.ErrTokenRevoked) {
			t.Fatalf("replay %d: %v", i, err)
		}
	}
	for _, jti := range dl.seen {
		if jti != pair.SessionID {
			t.Fatalf("the denylist was asked about %q, the token carries %q", jti, pair.SessionID)
		}
	}
}
