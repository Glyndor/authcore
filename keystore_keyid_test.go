package authcore_test

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"

	"github.com/Glyndor/authcore"
)

// relabelStore hands out the material of a real store under a KeyID of the
// test's choosing, which is what a custom Keys can do.
type relabelStore struct {
	inner authcore.KeyStore
	id    string
}

type relabelledKeys struct {
	authcore.Keys
	id string
}

func (k relabelledKeys) KeyID() string { return k.id }

func (s relabelStore) Load() (authcore.Keys, error) {
	keys, err := s.inner.Load()
	if err != nil {
		return nil, err
	}
	return relabelledKeys{keys, s.id}, nil
}

// New refuses a KeyStore whose Keys report an empty KeyID: the current key
// was registered under "" and a token with no kid header verified against
// it. A custom non-empty id is accepted, since the derivation is the store's
// business.
func TestNew_refusesAnEmptyKeyID(t *testing.T) {
	seed := bytes.Repeat([]byte{0x42}, ed25519.SeedSize)
	priv := ed25519.NewKeyFromSeed(seed)
	inner, err := authcore.NewKeyStoreFromKeys(priv, priv.Public().(ed25519.PublicKey), bytes.Repeat([]byte{0x11}, 32))
	if err != nil {
		t.Fatal(err)
	}
	cfg := authcore.DefaultConfig()
	cfg.EnableLogs = false

	cfg.KeyStore = relabelStore{inner, ""}
	_, err = authcore.New(cfg)
	if !errors.Is(err, authcore.ErrKeyManager) || !strings.Contains(err.Error(), "empty KeyID") {
		t.Fatalf("New with an empty KeyID = %v, want ErrKeyManager naming it", err)
	}

	cfg.KeyStore = relabelStore{inner, "release-2026-09"}
	ac, err := authcore.New(cfg)
	if err != nil {
		t.Fatalf("New with a custom KeyID: %v, want accepted", err)
	}
	if ac.Keys().KeyID() != "release-2026-09" {
		t.Fatalf("KeyID = %q, want the store's", ac.Keys().KeyID())
	}
}
