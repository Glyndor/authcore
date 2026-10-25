package binding

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
)

func fixture(t *testing.T) (ed25519.PublicKey, []byte) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	return pub, secret
}

func TestComputeIsStableAndHex(t *testing.T) {
	pub, secret := fixture(t)
	a, b := Compute(pub, secret), Compute(pub, secret)
	if a != b || len(a) != 64 || strings.Trim(a, "0123456789abcdef") != "" {
		t.Fatalf("unstable or malformed binding %q / %q", a, b)
	}
}

func TestMatches(t *testing.T) {
	pub, secret := fixture(t)
	otherPub, otherSecret := fixture(t)
	good := Compute(pub, secret)
	cases := []struct {
		name     string
		recorded string
		pub      ed25519.PublicKey
		secret   []byte
		want     bool
	}{
		{"same pair", good, pub, secret, true},
		{"other secret", good, pub, otherSecret, false},
		{"other public key", good, otherPub, secret, false},
		{"empty", "", pub, secret, false},
		{"truncated", good[:32], pub, secret, false},
		{"not hex", strings.Repeat("z", 64), pub, secret, false},
	}
	for _, c := range cases {
		if got := Matches(c.recorded, c.pub, c.secret); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}
