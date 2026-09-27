package jwt

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
)

// A previous key with the current key's id would replace the current key in
// the verification set, and every token then issued failed its own
// verification (measured 2026-09-25 with a KeyStore reporting a stale kid).
// New refuses it; a different previous key is registered as before.
func TestNew_refusesAPreviousKeyWithTheCurrentKeyID(t *testing.T) {
	p := newFakeProvider(t)
	cfg := DefaultConfig()
	cfg.PreviousPublicKeys = []ed25519.PublicKey{p.Keys().PublicKey()}
	_, err := New[struct{}](p, cfg)
	if !errors.Is(err, ErrInvalidConfig) || !strings.Contains(err.Error(), "has the current signing key's id") {
		t.Fatalf("New with the current key listed as previous = %v, want ErrInvalidConfig naming it", err)
	}

	cfg.PreviousPublicKeys = []ed25519.PublicKey{newFakeProvider(t).Keys().PublicKey()}
	j, err := New[struct{}](p, cfg)
	if err != nil {
		t.Fatalf("New with a different previous key: %v", err)
	}
	if len(j.verifyKeys) != 2 {
		t.Fatalf("%d verification keys, want 2", len(j.verifyKeys))
	}
}
