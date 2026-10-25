package jwt_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Glyndor/authcore/auth/jwt"
)

// refreshStore is the table the application keeps, as the package doc
// describes: one stored refresh hash per session, replaced atomically on
// rotation. The module supplies the hash and its constant-time comparison;
// the compare-and-swap is the application's half of the contract.
type refreshStore struct {
	mu   sync.Mutex
	hash string
}

func (s *refreshStore) load() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hash
}

// replace swaps old for next only while old is still the stored hash.
func (s *refreshStore) replace(old, next string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.hash != old {
		return false
	}
	s.hash = next
	return true
}

// Many requests present the same refresh token at once, which is what a stolen
// token used alongside the legitimate client looks like. Run through the
// documented flow, at most one of them gets a new pair.
func TestHostile_Rotation_concurrentUseOfOneRefreshTokenYieldsOneWinner(t *testing.T) {
	e := newEnv(t)
	m := e.module(t, jwt.Config{})
	pair, err := m.CreateTokens(subject, extra{Role: "user"})
	if err != nil {
		t.Fatal(err)
	}
	store := &refreshStore{hash: pair.RefreshTokenHash}

	const attackers = 64
	var (
		wg      sync.WaitGroup
		start   = make(chan struct{})
		winners atomic.Int64
		mu      sync.Mutex
		pairs   []*jwt.TokenPair
	)
	for i := 0; i < attackers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			stored := store.load()
			if !m.VerifyRefreshTokenHash(pair.RefreshToken, stored) {
				return
			}
			next, err := m.RotateTokens(pair.RefreshToken, extra{Role: "user"})
			if err != nil {
				t.Errorf("RotateTokens: %v", err)
				return
			}
			if store.replace(stored, next.RefreshTokenHash) {
				winners.Add(1)
				mu.Lock()
				pairs = append(pairs, next)
				mu.Unlock()
			}
		}()
	}
	close(start)
	wg.Wait()

	if got := winners.Load(); got != 1 {
		t.Fatalf("%d of %d concurrent presentations of one refresh token won, want exactly 1", got, attackers)
	}
	// The winner's token is the one the store now holds, and the old token no
	// longer matches it.
	if !m.VerifyRefreshTokenHash(pairs[0].RefreshToken, store.load()) {
		t.Fatal("the winner's refresh token does not match the stored hash")
	}
	if m.VerifyRefreshTokenHash(pair.RefreshToken, store.load()) {
		t.Fatal("the rotated-out refresh token still matches the stored hash")
	}
}

// Rotation produces a different refresh token and hash every time, even from
// the same input, so a hash-keyed compare-and-swap can tell the rotations apart.
func TestHostile_Rotation_everyRotationIsDistinguishable(t *testing.T) {
	e := newEnv(t)
	m := e.module(t, jwt.Config{})
	pair, _ := m.CreateTokens(subject, extra{})

	seenTokens := map[string]bool{pair.RefreshToken: true}
	seenHashes := map[string]bool{pair.RefreshTokenHash: true}
	var wg sync.WaitGroup
	var mu sync.Mutex
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			next, err := m.RotateTokens(pair.RefreshToken, extra{})
			if err != nil {
				t.Errorf("RotateTokens: %v", err)
				return
			}
			mu.Lock()
			defer mu.Unlock()
			if seenTokens[next.RefreshToken] || seenHashes[next.RefreshTokenHash] {
				t.Errorf("a rotation repeated an earlier refresh token or hash")
			}
			seenTokens[next.RefreshToken], seenHashes[next.RefreshTokenHash] = true, true
			if next.SessionID != pair.SessionID {
				t.Errorf("rotation changed the session id: %q -> %q", pair.SessionID, next.SessionID)
			}
		}()
	}
	wg.Wait()
}

// The stored refresh hash is compared exactly. Near misses of the right hash
// never match, and neither does a hash of a different token.
func TestHostile_Rotation_refreshHashComparisonIsExact(t *testing.T) {
	e := newEnv(t)
	m := e.module(t, jwt.Config{})
	pair, _ := m.CreateTokens(subject, extra{})
	other, _ := m.CreateTokens(subject, extra{})

	if !m.VerifyRefreshTokenHash(pair.RefreshToken, pair.RefreshTokenHash) {
		t.Fatal("control: the right hash was refused")
	}
	good := pair.RefreshTokenHash
	for name, stored := range map[string]string{
		"empty":            "",
		"uppercased":       strings.ToUpper(good),
		"prefix":           good[:len(good)-1],
		"extra char":       good + "0",
		"trailing NUL":     good + "\x00",
		"trailing newline": good + "\n",
		"leading space":    " " + good,
		"another token":    other.RefreshTokenHash,
		"all zero":         strings.Repeat("0", len(good)),
		"the token itself": pair.RefreshToken,
		"doubled":          good + good,
	} {
		if m.VerifyRefreshTokenHash(pair.RefreshToken, stored) {
			t.Errorf("%s: a wrong stored hash matched", name)
		}
	}
	for name, token := range map[string]string{
		"empty token":    "",
		"truncated":      pair.RefreshToken[:len(pair.RefreshToken)-1],
		"access token":   pair.AccessToken,
		"another token":  other.RefreshToken,
		"trailing space": pair.RefreshToken + " ",
	} {
		if m.VerifyRefreshTokenHash(token, pair.RefreshTokenHash) {
			t.Errorf("%s: matched the hash of a different token", name)
		}
	}
}

// Another deployment's secret yields other hashes, so a hash table lifted from
// one service cannot be replayed into another.
func TestHostile_Rotation_hashesAreBoundToTheRefreshSecret(t *testing.T) {
	a, b := newEnv(t), newEnv(t)
	ma, mb := a.module(t, jwt.Config{}), b.module(t, jwt.Config{})
	pair, _ := ma.CreateTokens(subject, extra{})
	hb, err := mb.HashRefreshToken(pair.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	if hb == pair.RefreshTokenHash {
		t.Fatal("two deployments hashed one token to the same value")
	}
	if mb.VerifyRefreshTokenHash(pair.RefreshToken, pair.RefreshTokenHash) {
		t.Fatal("a hash from another deployment verified")
	}
}

// Subjects are UUID v7 and nothing else, so an identifier shaped to confuse a
// downstream parser (traversal, SQL, whitespace, lookalike digits) never gets a
// signature.
func TestHostile_Subject_onlyAUUIDv7IsSigned(t *testing.T) {
	e := newEnv(t)
	m := e.module(t, jwt.Config{})
	for name, sub := range map[string]string{
		"empty":            "",
		"admin":            "admin",
		"uuid v4":          "0191b432-b5a7-4c4f-b2e6-7a3f1d2e0001",
		"uuid v1":          "0191b432-b5a7-1c4f-b2e6-7a3f1d2e0001",
		"nil uuid":         "00000000-0000-0000-0000-000000000000",
		"no dashes":        strings.ReplaceAll(subject, "-", ""),
		"braces":           "{" + subject + "}",
		"urn":              "urn:uuid:" + subject,
		"trailing newline": subject + "\n",
		"leading space":    " " + subject,
		"NUL":              subject[:35] + "\x00",
		"one char long":    subject + "0",
		"one char short":   subject[:35],
		"non-hex":          "0191b432-b5a7-7c4f-b2e6-7a3f1d2e000g",
		"arabic digit":     "0191b432-b5a7-7c4f-b2e6-7a3f1d2e000\u0661",
		"traversal":        "../../../../../../etc/passwd",
		"sql":              "' OR 1=1 --",
		"bad variant":      "0191b432-b5a7-7c4f-c2e6-7a3f1d2e0001",
	} {
		pair, err := m.CreateTokens(sub, extra{})
		if pair != nil || !errors.Is(err, jwt.ErrInvalidSubject) {
			t.Errorf("%s: CreateTokens = %+v, %v; want ErrInvalidSubject", name, pair, err)
		}
	}
	// The same subject in capitals is accepted and signed in lower case, so
	// one user cannot hold two spellings of one subject.
	pair, err := m.CreateTokens(strings.ToUpper(subject), extra{})
	if err != nil {
		t.Fatalf("an uppercase UUID v7 was refused: %v", err)
	}
	c, err := m.VerifyAccessToken(pair.AccessToken)
	if err != nil || c.Subject != subject {
		t.Fatalf("subject = %q, %v; want %q", c.Subject, err, subject)
	}
}

// Key rotation. A deployment that rotates its signing key lists the old public
// key so live sessions survive, and drops it when the old key is retired. A
// token under a retired key must stop verifying, and the new key's tokens must
// not verify anywhere that never trusted it.
func TestHostile_KeyRotation_retiredKeyStopsVerifying(t *testing.T) {
	oldEnv := newEnv(t)
	oldMod := oldEnv.module(t, jwt.Config{})
	oldPair, _ := oldMod.CreateTokens(subject, extra{})

	newEnvKeys := newEnv(t)
	withPrev := newEnvKeys.module(t, jwt.Config{PreviousPublicKeys: []ed25519.PublicKey{oldEnv.pub}})
	withoutPrev := newEnvKeys.module(t, jwt.Config{})

	if _, err := withPrev.VerifyAccessToken(oldPair.AccessToken); err != nil {
		t.Fatalf("control: a token under a listed previous key was refused: %v", err)
	}
	if p, err := withPrev.RotateTokens(oldPair.RefreshToken, extra{}); err != nil {
		t.Fatalf("control: rotating a refresh token under a previous key: %v", err)
	} else if h := decodeHeader(t, p.AccessToken); h["kid"] != newEnvKeys.kid {
		t.Fatalf("a rotation re-signed with kid %v, want the current key %q", h["kid"], newEnvKeys.kid)
	}

	if c, err := withoutPrev.VerifyAccessToken(oldPair.AccessToken); c != nil || !errors.Is(err, jwt.ErrTokenInvalid) {
		t.Fatalf("retired key's access token = %+v, %v; want ErrTokenInvalid", c, err)
	}
	if p, err := withoutPrev.RotateTokens(oldPair.RefreshToken, extra{}); p != nil || !errors.Is(err, jwt.ErrTokenInvalid) {
		t.Fatalf("retired key's refresh token = %+v, %v; want ErrTokenInvalid", p, err)
	}

	newPair, _ := withPrev.CreateTokens(subject, extra{})
	if c, err := oldMod.VerifyAccessToken(newPair.AccessToken); c != nil || !errors.Is(err, jwt.ErrTokenInvalid) {
		t.Fatalf("a token from a key this deployment never trusted = %+v, %v", c, err)
	}
}

// The previous-key list is trust configuration. Keys that would let a forger
// sign for any message, or that clash with the current key, are refused when
// the module is built.
func TestHostile_KeyRotation_unusablePreviousKeysAreRefusedAtConstruction(t *testing.T) {
	e := newEnv(t)
	hex := func(s string) ed25519.PublicKey {
		b := make([]byte, 32)
		for i := range b {
			b[i] = hexNibble(s[2*i])<<4 | hexNibble(s[2*i+1])
		}
		return b
	}
	smallOrder := map[string]ed25519.PublicKey{
		"identity point":          hex("0100000000000000000000000000000000000000000000000000000000000000"),
		"order 2 point":           hex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
		"order 4, y=0":            hex("0000000000000000000000000000000000000000000000000000000000000000"),
		"order 4, sign bit set":   hex("0000000000000000000000000000000000000000000000000000000000000080"),
		"order 8 point":           hex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
		"order 8 point, other":    hex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
		"identity, non-canonical": hex("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
		"order 4, non-canonical":  hex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
	}
	for name, key := range smallOrder {
		if _, err := jwt.New[extra](e.prov, jwt.Config{PreviousPublicKeys: []ed25519.PublicKey{key}}); !errors.Is(err, jwt.ErrInvalidConfig) {
			t.Errorf("%s: jwt.New = %v, want ErrInvalidConfig", name, err)
		}
	}
	for name, key := range map[string]ed25519.PublicKey{
		"empty":           {},
		"31 bytes":        make([]byte, 31),
		"33 bytes":        make([]byte, 33),
		"the current key": e.pub,
	} {
		if _, err := jwt.New[extra](e.prov, jwt.Config{PreviousPublicKeys: []ed25519.PublicKey{key}}); !errors.Is(err, jwt.ErrInvalidConfig) {
			t.Errorf("%s: jwt.New = %v, want ErrInvalidConfig", name, err)
		}
	}

	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := jwt.New[extra](e.prov, jwt.Config{PreviousPublicKeys: []ed25519.PublicKey{otherPub}}); err != nil {
		t.Fatalf("control: an ordinary previous key was refused: %v", err)
	}
}

func hexNibble(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	default:
		return c - 'a' + 10
	}
}

// The zero value and the nil pointer hold no keys. They refuse instead of
// signing with an empty one.
func TestHostile_Module_uninitialisedInstanceProducesNothing(t *testing.T) {
	var nilMod *jwt.JWT[extra]
	zero := &jwt.JWT[extra]{}
	for name, m := range map[string]*jwt.JWT[extra]{"nil": nilMod, "zero": zero} {
		if p, err := m.CreateTokens(subject, extra{}); p != nil || !errors.Is(err, jwt.ErrNotInitialised) {
			t.Errorf("%s CreateTokens = %+v, %v", name, p, err)
		}
		if c, err := m.VerifyAccessToken("a.b.c"); c != nil || !errors.Is(err, jwt.ErrNotInitialised) {
			t.Errorf("%s VerifyAccessToken = %+v, %v", name, c, err)
		}
		if p, err := m.RotateTokens("a.b.c", extra{}); p != nil || !errors.Is(err, jwt.ErrNotInitialised) {
			t.Errorf("%s RotateTokens = %+v, %v", name, p, err)
		}
	}
	if zero.VerifyRefreshTokenHash("t", "") {
		t.Error("a zero value verified a refresh hash")
	}
	if h, err := zero.HashRefreshToken("t"); h != "" || !errors.Is(err, jwt.ErrNotInitialised) {
		t.Errorf("zero HashRefreshToken = %q, %v", h, err)
	}
}
