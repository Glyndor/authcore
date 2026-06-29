package jwt

import (
	"crypto/ed25519"
	"errors"
	"testing"
)

// TestRotation_previousKeyStillVerifies models the overlap window: a new module
// signs with a fresh key but lists the old public key, so tokens minted by the
// old key keep verifying.
func TestRotation_previousKeyStillVerifies(t *testing.T) {
	provOld := newFakeProvider(t)
	jOld := newTestJWT[struct{}](t, provOld, DefaultConfig())
	pair, err := jOld.CreateTokens(testSubject, struct{}{})
	if err != nil {
		t.Fatalf("CreateTokens: %v", err)
	}

	cfg := DefaultConfig()
	cfg.PreviousPublicKeys = []ed25519.PublicKey{provOld.Keys().PublicKey()}
	jNew := newTestJWT[struct{}](t, newFakeProvider(t), cfg)

	if _, err := jNew.VerifyAccessToken(pair.AccessToken); err != nil {
		t.Errorf("access token from the rotated-out key should still verify, got %v", err)
	}
	// Rotation off the old refresh token must also work during the overlap.
	if _, err := jNew.RotateTokens(pair.RefreshToken, struct{}{}); err != nil {
		t.Errorf("refresh token from the rotated-out key should still rotate, got %v", err)
	}
}

// TestRotation_currentKeyStillVerifies confirms the new module's own tokens
// verify alongside the accepted previous key.
func TestRotation_currentKeyStillVerifies(t *testing.T) {
	provOld := newFakeProvider(t)
	cfg := DefaultConfig()
	cfg.PreviousPublicKeys = []ed25519.PublicKey{provOld.Keys().PublicKey()}
	jNew := newTestJWT[struct{}](t, newFakeProvider(t), cfg)

	pair, _ := jNew.CreateTokens(testSubject, struct{}{})
	if _, err := jNew.VerifyAccessToken(pair.AccessToken); err != nil {
		t.Errorf("current-key token must verify, got %v", err)
	}
}

// TestRotation_unlistedKeyRejected confirms a token signed by a key that is
// neither current nor listed is refused.
func TestRotation_unlistedKeyRejected(t *testing.T) {
	provOld := newFakeProvider(t)
	jOld := newTestJWT[struct{}](t, provOld, DefaultConfig())
	pair, _ := jOld.CreateTokens(testSubject, struct{}{})

	jNew := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig()) // no previous keys
	_, err := jNew.VerifyAccessToken(pair.AccessToken)
	if !errors.Is(err, ErrTokenInvalid) {
		t.Errorf("expected ErrTokenInvalid for an unlisted key, got %v", err)
	}
}

func TestRotation_badPreviousKeyRejectedAtNew(t *testing.T) {
	cfg := DefaultConfig()
	cfg.PreviousPublicKeys = []ed25519.PublicKey{[]byte("too-short")}
	if _, err := New[struct{}](newFakeProvider(t), cfg); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("expected ErrInvalidConfig for a wrong-length previous key, got %v", err)
	}
}
