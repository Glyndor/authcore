package configcopy

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/jwt"
	"github.com/Glyndor/authcore/tests/hostile/misuse/hostiletest"
)

func newJWT(t *testing.T, e *hostiletest.Env, cfg jwt.Config) *jwt.JWT[struct{}] {
	t.Helper()
	m, err := jwt.New[struct{}](e.AC, cfg)
	if err != nil {
		t.Fatalf("jwt.New: %v", err)
	}
	return m
}

// The audience slice stays the caller's. Rewriting its first entry after New
// must not change which audience the module issues and accepts.
func TestMisuse_ConfigCopy_jwtAudienceSliceIsSnapshotted(t *testing.T) {
	e := hostiletest.NewEnv(t)
	cfg := jwt.Config{Audience: []string{"aud-a"}}
	m := newJWT(t, e, cfg)
	cfg.Audience[0] = "aud-evil"

	pair, err := m.CreateTokens(hostiletest.Subject, struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newJWT(t, e, jwt.Config{Audience: []string{"aud-a"}}).VerifyAccessToken(pair.AccessToken); err != nil {
		t.Fatalf("the token no longer carries the audience the module was built with: %v", err)
	}
	if _, err := newJWT(t, e, jwt.Config{Audience: []string{"aud-evil"}}).VerifyAccessToken(pair.AccessToken); err == nil {
		t.Fatal("the token carries the audience the caller wrote after New")
	}
	evil, err := newJWT(t, e, jwt.Config{Audience: []string{"aud-evil"}}).CreateTokens(hostiletest.Subject, struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.VerifyAccessToken(evil.AccessToken); err == nil {
		t.Fatal("the module accepts the audience the caller wrote after New")
	}
}

// PreviousPublicKeys holds slices of key bytes. Wiping one after New must not
// break the rotation overlap, and replacing one must not add a trusted key.
func TestMisuse_ConfigCopy_jwtPreviousKeysAreSnapshotted(t *testing.T) {
	e := hostiletest.NewEnv(t)
	old := hostiletest.NewEnv(t)
	stranger := hostiletest.NewEnv(t)

	oldTok, err := newJWT(t, old, jwt.Config{}).CreateTokens(hostiletest.Subject, struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	strangerTok, err := newJWT(t, stranger, jwt.Config{}).CreateTokens(hostiletest.Subject, struct{}{})
	if err != nil {
		t.Fatal(err)
	}

	cfg := jwt.Config{PreviousPublicKeys: []ed25519.PublicKey{old.Mat.Pub}}
	m := newJWT(t, e, cfg)
	if _, err := m.VerifyAccessToken(oldTok.AccessToken); err != nil {
		t.Fatalf("control: the overlap key does not verify before any mutation: %v", err)
	}

	wipe(old.Mat.Pub)
	cfg.PreviousPublicKeys[0] = stranger.Mat.Pub
	cfg.PreviousPublicKeys = append(cfg.PreviousPublicKeys, stranger.Mat.Pub)

	if _, err := m.VerifyAccessToken(oldTok.AccessToken); err != nil {
		t.Errorf("wiping the caller's copy of the previous key broke verification: %v", err)
	}
	if _, err := m.VerifyAccessToken(strangerTok.AccessToken); err == nil {
		t.Error("a key the caller put into the slice after New is trusted")
	}
}

// Durations are values, but the expiry the module stamps on a token is read
// from its own snapshot, so editing the caller's struct changes nothing.
func TestMisuse_ConfigCopy_jwtLifetimesAreSnapshotted(t *testing.T) {
	e := hostiletest.NewEnv(t)
	cfg := jwt.Config{AccessTokenTTL: time.Minute, RefreshTokenTTL: time.Hour}
	m := newJWT(t, e, cfg)
	cfg.AccessTokenTTL = 24 * time.Hour
	cfg.RefreshTokenTTL = 365 * 24 * time.Hour

	pair, err := m.CreateTokens(hostiletest.Subject, struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Until(pair.AccessTokenExpiresAt); d > 2*time.Minute {
		t.Errorf("access token lives %s after the caller raised the TTL", d)
	}
	if d := time.Until(pair.RefreshTokenExpiresAt); d > 2*time.Hour {
		t.Errorf("refresh token lives %s after the caller raised the TTL", d)
	}
}
