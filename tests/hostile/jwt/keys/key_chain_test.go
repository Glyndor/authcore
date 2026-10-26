// Package keys attacks key handling in the JWT module: key chains across
// generations and kid providers.
package keys

import (
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/Glyndor/authcore/auth/jwt"
	"github.com/Glyndor/authcore/tests/hostile/jwt/hostiletest"
)

// A deployment rotates its signing key several times. Each generation lists the
// public keys of the ones before it. Tokens of every listed generation keep
// verifying and rotating, and only the newest key signs. Dropping the oldest
// from the list ends exactly that generation and none other.
func TestHostile_KeyChain_everyListedGenerationVerifiesAndOnlyThoseDo(t *testing.T) {
	const generations = 6
	envs := make([]*hostiletest.Env, generations)
	pairs := make([]*jwt.TokenPair, generations)
	for i := range envs {
		envs[i] = hostiletest.NewEnv(t)
		p, err := envs[i].Module(t, jwt.Config{}).CreateTokens(hostiletest.Subject, hostiletest.Extra{Role: "gen"})
		if err != nil {
			t.Fatal(err)
		}
		pairs[i] = p
	}

	previous := func(from int) []ed25519.PublicKey {
		var keys []ed25519.PublicKey
		for i := from; i < generations-1; i++ {
			keys = append(keys, envs[i].Pub)
		}
		return keys
	}

	newest := envs[generations-1]
	for oldest := 0; oldest < generations-1; oldest++ {
		m := newest.Module(t, jwt.Config{PreviousPublicKeys: previous(oldest)})
		for g := 0; g < generations; g++ {
			listed := g >= oldest
			_, errAccess := m.VerifyAccessToken(pairs[g].AccessToken)
			rotated, errRotate := m.RotateTokens(pairs[g].RefreshToken, hostiletest.Extra{})
			if listed {
				if errAccess != nil || errRotate != nil {
					t.Errorf("list from %d: generation %d is listed but refused: access=%v rotate=%v", oldest, g, errAccess, errRotate)
				}
				if errRotate == nil {
					if h := hostiletest.DecodeHeader(t, rotated.AccessToken); h["kid"] != newest.Kid {
						t.Errorf("list from %d: a rotation of generation %d was signed with kid %v, want the newest %q", oldest, g, h["kid"], newest.Kid)
					}
				}
				continue
			}
			if !errors.Is(errAccess, jwt.ErrTokenInvalid) || !errors.Is(errRotate, jwt.ErrTokenInvalid) {
				t.Errorf("list from %d: generation %d is not listed but verified: access=%v rotate=%v", oldest, g, errAccess, errRotate)
			}
		}
	}
}

// A refresh token carried through several rotations across a key change keeps
// its session id, and the rotation is signed by the new key only. After the
// old key leaves the list the pre-rotation token is dead and the rotated one
// lives.
func TestHostile_KeyChain_aSessionSurvivesTheKeyChangeThroughRotation(t *testing.T) {
	oldEnv, newEnvKeys := hostiletest.NewEnv(t), hostiletest.NewEnv(t)
	oldMod := oldEnv.Module(t, jwt.Config{})
	first, err := oldMod.CreateTokens(hostiletest.Subject, hostiletest.Extra{})
	if err != nil {
		t.Fatal(err)
	}

	overlap := newEnvKeys.Module(t, jwt.Config{PreviousPublicKeys: []ed25519.PublicKey{oldEnv.Pub}})
	moved, err := overlap.RotateTokens(first.RefreshToken, hostiletest.Extra{})
	if err != nil {
		t.Fatalf("rotation during the overlap: %v", err)
	}
	if moved.SessionID != first.SessionID {
		t.Errorf("session id changed across the key change: %s -> %s", first.SessionID, moved.SessionID)
	}

	alone := newEnvKeys.Module(t, jwt.Config{})
	if _, err := alone.VerifyAccessToken(moved.AccessToken); err != nil {
		t.Errorf("a token signed by the new key fails once the overlap ends: %v", err)
	}
	if _, err := alone.RotateTokens(moved.RefreshToken, hostiletest.Extra{}); err != nil {
		t.Errorf("a rotated refresh token fails once the overlap ends: %v", err)
	}
	if _, err := alone.RotateTokens(first.RefreshToken, hostiletest.Extra{}); !errors.Is(err, jwt.ErrTokenInvalid) {
		t.Errorf("the pre-rotation token after the overlap = %v, want ErrTokenInvalid", err)
	}
}
