package keymanager_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager"
)

func genPair(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	return priv, pub
}

func TestFromKeys_valid(t *testing.T) {
	priv, pub := genPair(t)
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)

	km, err := keymanager.FromKeys(priv, pub, secret)
	if err != nil {
		t.Fatalf("FromKeys: %v", err)
	}
	if km.KeyID() == "" {
		t.Error("KeyID not derived")
	}
	if km.Dir() != "" {
		t.Errorf("in-memory manager Dir() = %q, want empty", km.Dir())
	}
}

func TestFromKeys_rejectsBadInput(t *testing.T) {
	priv, pub := genPair(t)
	_, otherPub := genPair(t)
	good := make([]byte, 32)

	cases := map[string]func() error{
		"mismatched pair": func() error { _, e := keymanager.FromKeys(priv, otherPub, good); return e },
		"short secret":    func() error { _, e := keymanager.FromKeys(priv, pub, []byte("x")); return e },
		"nil private":     func() error { _, e := keymanager.FromKeys(nil, pub, good); return e },
	}
	for name, fn := range cases {
		if fn() == nil {
			t.Errorf("%s: expected an error, got nil", name)
		}
	}
}

// resized returns a copy of b cut or zero-padded to n bytes.
func resized(b []byte, n int) []byte {
	out := make([]byte, n)
	copy(out, b)
	return out
}

// Every fixture is valid except for the one rule its case names, and every
// rejection is checked by the message only that rule produces. "err != nil"
// would be satisfied by whichever rule happened to fire first.
func TestValidateMaterial(t *testing.T) {
	priv, pub := genPair(t)
	otherPriv, otherPub := genPair(t)
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)

	tests := []struct {
		name   string
		priv   ed25519.PrivateKey
		pub    ed25519.PublicKey
		secret []byte
		want   string // empty means the material must be accepted
	}{
		{"valid", priv, pub, secret, ""},
		{"valid second pair", otherPriv, otherPub, secret, ""},
		{"private key short", resized(priv, 63), pub, secret, "private key has wrong length: got 63"},
		{"private key long", resized(priv, 65), pub, secret, "private key has wrong length: got 65"},
		{"public key short", priv, resized(pub, 31), secret, "public key has wrong length: got 31"},
		{"public key long", priv, resized(pub, 33), secret, "public key has wrong length: got 33"},
		{"public key of another pair", priv, otherPub, secret, "public key does not match private key"},
		{"refresh secret short", priv, pub, resized(secret, 31), "refresh secret has wrong length: got 31"},
		{"refresh secret long", priv, pub, resized(secret, 33), "refresh secret has wrong length: got 33"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := keymanager.ValidateMaterial(tt.priv, tt.pub, tt.secret)
			if tt.want == "" {
				if err != nil {
					t.Fatalf("valid material refused: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("material accepted; want an error containing %q", tt.want)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("wrong rule fired\n got: %v\nwant fragment: %q", err, tt.want)
			}

			// FromKeys must apply the same rules, not a copy of them.
			if _, ferr := keymanager.FromKeys(tt.priv, tt.pub, tt.secret); ferr == nil || ferr.Error() != err.Error() {
				t.Errorf("FromKeys disagrees with ValidateMaterial: %v", ferr)
			}
		})
	}
}

func TestFromPEM_roundTripAndGarbage(t *testing.T) {
	priv, pub := genPair(t)
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	privDER, _ := x509.MarshalPKCS8PrivateKey(priv)
	pubDER, _ := x509.MarshalPKIXPublicKey(pub)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	if _, err := keymanager.FromPEM(privPEM, pubPEM, secret); err != nil {
		t.Fatalf("FromPEM round-trip: %v", err)
	}
	if _, err := keymanager.FromPEM([]byte("garbage"), pubPEM, secret); err == nil {
		t.Error("expected an error for a non-PEM private key")
	}
}
