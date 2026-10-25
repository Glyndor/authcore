package verify_test

import (
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/Glyndor/authcore/auth/jwt/internal/jwterr"
	"github.com/Glyndor/authcore/auth/jwt/internal/jwttest"
)

// TestRotation_previousKeyStillVerifies models the overlap window: a new module
// signs with a fresh key but lists the old public key, so tokens minted by the
// old key keep verifying.
func TestRotation_previousKeyStillVerifies(t *testing.T) {
	provOld := jwttest.NewKeys(t)
	jOld := jwttest.NewRig[struct{}](provOld, jwttest.DefaultConfig())
	pair, err := jOld.CreateTokens(jwttest.Subject, struct{}{})
	if err != nil {
		t.Fatalf("CreateTokens: %v", err)
	}

	cfg := jwttest.DefaultConfig()
	cfg.PreviousPublicKeys = []ed25519.PublicKey{provOld.Pub}
	jNew := newRig[struct{}](t, cfg)

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
	provOld := jwttest.NewKeys(t)
	cfg := jwttest.DefaultConfig()
	cfg.PreviousPublicKeys = []ed25519.PublicKey{provOld.Pub}
	jNew := newRig[struct{}](t, cfg)

	pair, _ := jNew.CreateTokens(jwttest.Subject, struct{}{})
	if _, err := jNew.VerifyAccessToken(pair.AccessToken); err != nil {
		t.Errorf("current-key token must verify, got %v", err)
	}
}

// TestRotation_unlistedKeyRejected confirms a token signed by a key that is
// neither current nor listed is refused.
func TestRotation_unlistedKeyRejected(t *testing.T) {
	provOld := jwttest.NewKeys(t)
	jOld := jwttest.NewRig[struct{}](provOld, jwttest.DefaultConfig())
	pair, _ := jOld.CreateTokens(jwttest.Subject, struct{}{})

	jNew := newRig[struct{}](t, jwttest.DefaultConfig()) // no previous keys
	_, err := jNew.VerifyAccessToken(pair.AccessToken)
	if !errors.Is(err, jwterr.ErrTokenInvalid) {
		t.Errorf("expected ErrTokenInvalid for an unlisted key, got %v", err)
	}
}
