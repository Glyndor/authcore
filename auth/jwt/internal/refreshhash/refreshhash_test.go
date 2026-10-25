package refreshhash_test

import (
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/jwt/internal/jwttest"
)

func newRig[T any](t *testing.T, cfg jwttest.Config) *jwttest.Rig[T] {
	t.Helper()
	return jwttest.NewRig[T](jwttest.NewKeys(t), cfg)
}

func TestHashRefreshToken_isDeterministic(t *testing.T) {
	j := newRig[struct{}](t, jwttest.DefaultConfig())
	pair, _ := j.CreateTokens(jwttest.Subject, struct{}{})

	h1 := j.HashRefreshToken(pair.RefreshToken)
	h2 := j.HashRefreshToken(pair.RefreshToken)
	if h1 != h2 {
		t.Errorf("HashRefreshToken is not deterministic: %q != %q", h1, h2)
	}
}

func TestHashRefreshToken_differentTokensDifferentHashes(t *testing.T) {
	j := newRig[struct{}](t, jwttest.DefaultConfig())
	p1, _ := j.CreateTokens(jwttest.Subject, struct{}{})
	p2, _ := j.CreateTokens(jwttest.Subject, struct{}{})

	h1 := j.HashRefreshToken(p1.RefreshToken)
	h2 := j.HashRefreshToken(p2.RefreshToken)
	if h1 == h2 {
		t.Error("different refresh tokens must produce different HMAC digests")
	}
}

func TestHashRefreshToken_differentSecretsDifferentHashes(t *testing.T) {
	j1 := newRig[struct{}](t, jwttest.DefaultConfig())
	j2 := newRig[struct{}](t, jwttest.DefaultConfig())

	// Sign a token with j1's key, hash it with both modules' secrets.
	pair, _ := j1.CreateTokens(jwttest.Subject, struct{}{})

	h1 := j1.HashRefreshToken(pair.RefreshToken)
	h2 := j2.HashRefreshToken(pair.RefreshToken)

	// Different HMAC secrets must produce different digests.
	if h1 == h2 {
		t.Error("same token hashed with different secrets should produce different results")
	}
}

// ---- VerifyRefreshTokenHash() -----------------------------------------------

func TestVerifyRefreshTokenHash_matchesStoredHash(t *testing.T) {
	j := newRig[struct{}](t, jwttest.DefaultConfig())
	pair, _ := j.CreateTokens(jwttest.Subject, struct{}{})

	if !j.VerifyRefreshTokenHash(pair.RefreshToken, pair.RefreshTokenHash) {
		t.Error("VerifyRefreshTokenHash returned false for a valid token/hash pair")
	}
}

func TestVerifyRefreshTokenHash_modifiedTokenDoesNotMatch(t *testing.T) {
	j := newRig[struct{}](t, jwttest.DefaultConfig())
	pair, _ := j.CreateTokens(jwttest.Subject, struct{}{})

	if j.VerifyRefreshTokenHash(pair.RefreshToken+"X", pair.RefreshTokenHash) {
		t.Error("VerifyRefreshTokenHash returned true for a modified token")
	}
}

func TestVerifyRefreshTokenHash_modifiedHashDoesNotMatch(t *testing.T) {
	j := newRig[struct{}](t, jwttest.DefaultConfig())
	pair, _ := j.CreateTokens(jwttest.Subject, struct{}{})

	badHash := strings.Repeat("0", 64)
	if j.VerifyRefreshTokenHash(pair.RefreshToken, badHash) {
		t.Error("VerifyRefreshTokenHash returned true for a tampered hash")
	}
}

func TestVerifyRefreshTokenHash_emptyTokenDoesNotMatch(t *testing.T) {
	j := newRig[struct{}](t, jwttest.DefaultConfig())
	pair, _ := j.CreateTokens(jwttest.Subject, struct{}{})

	if j.VerifyRefreshTokenHash("", pair.RefreshTokenHash) {
		t.Error("VerifyRefreshTokenHash returned true for empty token")
	}
}

func TestVerifyRefreshTokenHash_emptyHashDoesNotMatch(t *testing.T) {
	j := newRig[struct{}](t, jwttest.DefaultConfig())
	pair, _ := j.CreateTokens(jwttest.Subject, struct{}{})

	if j.VerifyRefreshTokenHash(pair.RefreshToken, "") {
		t.Error("VerifyRefreshTokenHash returned true for empty stored hash")
	}
}

func TestVerifyRefreshTokenHash_consistentWithHashRefreshToken(t *testing.T) {
	j := newRig[struct{}](t, jwttest.DefaultConfig())
	pair, _ := j.CreateTokens(jwttest.Subject, struct{}{})

	hash := j.HashRefreshToken(pair.RefreshToken)
	if !j.VerifyRefreshTokenHash(pair.RefreshToken, hash) {
		t.Error("VerifyRefreshTokenHash disagrees with HashRefreshToken for the same input")
	}
}

// Known answer: the refresh-token hash is HMAC-SHA256 of the token string
// under the refresh secret, hex encoded. The expected value was computed
// outside Go. A change here silently invalidates every stored refresh hash.
func TestHashRefreshToken_knownAnswer(t *testing.T) {
	keys := jwttest.NewKeys(t)
	keys.Secret = []byte("0123456789abcdef0123456789abcdef")
	j := jwttest.NewRig[struct{}](keys, jwttest.DefaultConfig())
	got := j.HashRefreshToken("refresh-token-under-test")
	const want = "b0e155640d4a6669dd817a7229216277c5fc58547e19f00c9eac83de94b6a15f"
	if got != want {
		t.Fatalf("HashRefreshToken = %s, want %s: the stored-hash format changed", got, want)
	}
}
