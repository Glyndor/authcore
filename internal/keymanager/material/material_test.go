package material

import (
	"crypto/ed25519"
	"crypto/rand"
	"regexp"
	"strings"
	"testing"
)

func genPair(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	return priv, pub
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
func TestValidate(t *testing.T) {
	priv, pub := genPair(t)
	otherPriv, otherPub := genPair(t)
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)

	// The seed of one key followed by the public half of another. Passed with
	// that other public key it satisfies both length rules and the comparison
	// against priv.Public(), so only the derivation from the seed refuses it.
	spliced := append(append(ed25519.PrivateKey{}, priv.Seed()...), otherPub...)

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
		{"spliced private key", spliced, otherPub, secret, "private key is inconsistent"},
		{"public key of another pair", priv, otherPub, secret, "public key does not match private key"},
		{"refresh secret short", priv, pub, resized(secret, 31), "refresh secret has wrong length: got 31"},
		{"refresh secret long", priv, pub, resized(secret, 33), "refresh secret has wrong length: got 33"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Validate(tt.priv, tt.pub, tt.secret)
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
		})
	}
}

func TestValidate_errorNeverContainsKeyBytes(t *testing.T) {
	priv, pub := genPair(t)
	err := Validate(priv, pub, []byte("short"))
	if err == nil {
		t.Fatal("short secret accepted")
	}
	if strings.Contains(err.Error(), string(priv)) || strings.Contains(err.Error(), "short") {
		t.Fatalf("the error echoes key material: %v", err)
	}
}

func TestKeyID_is16LowercaseHexCharacters(t *testing.T) {
	_, pub := genPair(t)
	if id := KeyID(pub); !regexp.MustCompile(`^[0-9a-f]{16}$`).MatchString(id) {
		t.Fatalf("KeyID = %q, want 16 lowercase hex characters", id)
	}
}

func TestKeyID_isDeterministicAndKeySpecific(t *testing.T) {
	_, pub := genPair(t)
	_, other := genPair(t)
	if first, second := KeyID(pub), KeyID(pub); first != second {
		t.Fatal("KeyID is not deterministic")
	}
	if KeyID(pub) == KeyID(other) {
		t.Fatal("two different keys share an id")
	}
}
