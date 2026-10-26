package model

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/jwt"
	"github.com/Glyndor/authcore/tests/hostile/e2e/hostiletest"
)

const (
	accessTTL  = 10 * time.Minute
	refreshTTL = time.Hour
)

var ctx = context.Background()

// tok is a token the model knows the story of: what it is, which session it
// belongs to and the virtual instant it was issued.
type tok struct {
	wire   string
	access bool
	sid    string
	at     time.Duration
}

// jwtModel is the oracle and the system under test side by side. The oracle is
// the rules of docs/modules/jwt.md: a token is accepted when the module
// issued it, it is of the type asked for, it is younger than its TTL plus the
// configured clock skew leeway, and its
// session is not on the denylist while the denylist can answer.
type jwtModel struct {
	t       *testing.T
	tr      *trace
	r       *rng
	env     *hostiletest.Env
	foreign *hostiletest.Env
	mod     *jwt.JWT[hostiletest.Extra]
	deny    *hostiletest.Denylist

	now     time.Duration
	toks    []tok
	revoked map[string]bool
	down    bool
	leeway  time.Duration
	seen    map[string]int // verdict counts by operation and outcome
}

func newJWTModel(t *testing.T, seed uint64, leeway time.Duration) *jwtModel {
	t.Helper()
	env := hostiletest.NewEnv(t)
	deny := hostiletest.NewDenylist()
	mod := env.JWT(t, jwt.Config{AccessTokenTTL: accessTTL, RefreshTokenTTL: refreshTTL, ClockSkewLeeway: leeway, Denylist: deny})
	return &jwtModel{
		t: t, tr: &trace{seed: seed}, r: &rng{state: seed}, env: env, foreign: hostiletest.NewEnv(t),
		mod: mod, deny: deny, leeway: leeway, revoked: map[string]bool{}, seen: map[string]int{},
	}
}

// accepts is the oracle: would a correct implementation accept tk presented as
// an access token (wantAccess) or as a refresh token.
func (m *jwtModel) accepts(tk tok, wantAccess bool) bool {
	ttl := refreshTTL
	if tk.access {
		ttl = accessTTL
	}
	return tk.access == wantAccess && m.now-tk.at < ttl+m.leeway && !m.revoked[tk.sid] && !m.down
}

// wire is the token as the adversary replays it now: the same bytes the module
// issued, with the clock moved on by the time elapsed since.
func (m *jwtModel) wire(tk tok) string {
	return hostiletest.Age(m.t, m.env, tk.wire, m.now-tk.at)
}

// compare checks the library's verdict against the oracle's.
func (m *jwtModel) compare(op string, err error, want bool) {
	m.t.Helper()
	m.seen[op+" accepted="+strconv.FormatBool(want)]++
	switch got := err == nil; {
	case got && !want:
		m.tr.fail(m.t, "%s: the library accepted what the model rejects (more permissive)", op)
	case !got && want:
		m.tr.fail(m.t, "%s: the library rejected what the model accepts (%v)", op, err)
	}
}

func (m *jwtModel) login() {
	subject := pick(m.r, []string{hostiletest.Subject, hostiletest.Other})
	pair, err := m.mod.CreateTokens(subject, hostiletest.Extra{})
	if err != nil {
		m.tr.fail(m.t, "login: %v", err)
	}
	m.toks = append(m.toks,
		tok{wire: pair.AccessToken, access: true, sid: pair.SessionID, at: m.now},
		tok{wire: pair.RefreshToken, sid: pair.SessionID, at: m.now})
	m.tr.add("login sid=%s at=%s", pair.SessionID[24:], m.now)
}

func (m *jwtModel) verify(tk tok) {
	_, err := m.mod.VerifyAccessTokenContext(ctx, m.wire(tk))
	m.tr.add("verify access=%v sid=%s age=%s revoked=%v -> %v", tk.access, tk.sid[24:], m.now-tk.at, m.revoked[tk.sid], err == nil)
	m.compare("verify", err, m.accepts(tk, true))
}

func (m *jwtModel) rotate(tk tok) {
	pair, err := m.mod.RotateTokensContext(ctx, m.wire(tk), hostiletest.Extra{})
	m.tr.add("rotate access=%v sid=%s age=%s revoked=%v -> %v", tk.access, tk.sid[24:], m.now-tk.at, m.revoked[tk.sid], err == nil)
	m.compare("rotate", err, m.accepts(tk, false))
	if err != nil {
		return
	}
	if pair.SessionID != tk.sid {
		m.tr.fail(m.t, "rotate: session id changed from %s to %s", tk.sid, pair.SessionID)
	}
	m.toks = append(m.toks,
		tok{wire: pair.AccessToken, access: true, sid: pair.SessionID, at: m.now},
		tok{wire: pair.RefreshToken, sid: pair.SessionID, at: m.now})
}

// reject presents a token the model knows is not acceptable, both ways.
func (m *jwtModel) reject(what, wire string) {
	_, errA := m.mod.VerifyAccessTokenContext(ctx, wire)
	_, errR := m.mod.RotateTokensContext(ctx, wire, hostiletest.Extra{})
	m.tr.add("%s -> verify=%v rotate=%v", what, errA == nil, errR == nil)
	if errA == nil || errR == nil {
		m.tr.fail(m.t, "%s was accepted (verify ok=%v, rotate ok=%v)", what, errA == nil, errR == nil)
	}
}

// tamper changes one character of one segment in the middle, where it cannot
// land on unused padding bits, or splices segments of two tokens.
func (m *jwtModel) tamper(a, b tok) {
	wa, wb := m.wire(a), m.wire(b)
	parts := strings.Split(wa, ".")
	other := strings.Split(wb, ".")
	switch m.r.intn(5) {
	case 0, 1, 2:
		i := m.r.intn(3)
		seg := []byte(parts[i])
		mid := len(seg) / 2
		if seg[mid] == 'A' {
			seg[mid] = 'B'
		} else {
			seg[mid] = 'A'
		}
		parts[i] = string(seg)
		m.reject("one character changed in segment "+string(rune('0'+i)), strings.Join(parts, "."))
	case 3:
		if other[2] == parts[2] {
			return // the same signature spliced onto itself is the genuine token
		}
		m.reject("signature of another token", parts[0]+"."+parts[1]+"."+other[2])
	default:
		m.reject("signed by a key the module does not trust", hostiletest.Age(m.t, m.foreign, wa, 0))
	}
}

// recent picks a token, usually one of the latest few: an adversary replays what
// it just saw far more often than what is long gone, and a model that only
// replays old tokens would watch everything expire.
func (m *jwtModel) recent() tok {
	if m.r.intn(10) < 7 && len(m.toks) > 6 {
		return m.toks[len(m.toks)-1-m.r.intn(6)]
	}
	return pick(m.r, m.toks)
}

func (m *jwtModel) step() {
	if len(m.toks) == 0 {
		m.login()
		return
	}
	tk := m.recent()
	switch n := m.r.intn(100); {
	case n < 12:
		m.login()
	case n < 42:
		m.verify(tk)
	case n < 64:
		m.rotate(tk)
	case n < 67:
		m.revoked[tk.sid] = true
		m.deny.Add(tk.sid)
		m.tr.add("revoke sid=%s", tk.sid[24:])
	case n < 77:
		d := pick(m.r, []int{1, 1, 5, 9, 10, 11, 30, 60})
		m.now += minutes(d)
		m.tr.add("advance %dm -> %s", d, m.now)
	case n < 80:
		m.down = !m.down
		m.deny.SetDown(m.down)
		m.tr.add("denylist down=%v", m.down)
	default:
		m.tamper(tk, m.recent())
	}
}

// Whatever the sequence, the library is never more permissive than the model,
// and (as a check on the model) not stricter either.
func TestE2E_Model_jwtNeverAcceptsWhatTheModelRejects(t *testing.T) {
	total := map[string]int{}
	for _, leeway := range []time.Duration{0, 2 * time.Minute} {
		for _, seed := range seeds(t) {
			m := newJWTModel(t, seed, leeway)
			for i := 0; i < opsPerSeq; i++ {
				m.step()
			}
			for k, v := range m.seen {
				total[k] += v
			}
		}
	}
	// A model that only ever expects one verdict proves nothing about the other.
	for _, k := range []string{"verify accepted=true", "verify accepted=false", "rotate accepted=true", "rotate accepted=false"} {
		if total[k] < 100 {
			t.Errorf("%q was exercised %d times, want at least 100 (%v)", k, total[k], total)
		}
	}
}
