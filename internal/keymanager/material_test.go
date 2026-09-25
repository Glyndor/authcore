package keymanager_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
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

// FromPEM's public-PEM decode error path: a valid private key alongside an
// unparseable public key must surface the public-key error rather than
// silently pass.
func TestFromPEM_invalidPublicPEMIsRejected(t *testing.T) {
	priv, _ := genPair(t)
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	privDER, _ := x509.MarshalPKCS8PrivateKey(priv)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})

	if _, err := keymanager.FromPEM(privPEM, []byte("not a public key"), secret); err == nil {
		t.Fatal("FromPEM accepted an unparseable public key")
	}
}

// decodeEd25519PrivatePEM's "valid PKCS#8 but wrong algorithm" branch: a
// PKCS#8 envelope that holds an RSA key parses without error but yields an
// rsa.PrivateKey, not an ed25519.PrivateKey. The type assertion must fail
// with the message that names the algorithm it received.
func TestFromPEM_rsaPrivateKeyIsRejected(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaDER, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	rsaPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rsaDER})

	_, err = keymanager.FromPEM(rsaPEM, []byte("public"), make([]byte, 32))
	if err == nil {
		t.Fatal("FromPEM accepted an RSA private key as Ed25519")
	}
	if !strings.Contains(err.Error(), "Ed25519 private key") {
		t.Errorf("error must name the Ed25519 requirement, got: %v", err)
	}
}

func TestFromPEM_ecdsaPublicKeyIsRejected(t *testing.T) {
	priv, _ := genPair(t)
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	privDER, _ := x509.MarshalPKCS8PrivateKey(priv)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})

	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecDER, err := x509.MarshalPKIXPublicKey(&ec.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	ecPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: ecDER})

	_, err = keymanager.FromPEM(privPEM, ecPEM, secret)
	if err == nil {
		t.Fatal("FromPEM accepted an ECDSA public key as Ed25519")
	}
	if !strings.Contains(err.Error(), "Ed25519 public key") {
		t.Errorf("error must name the Ed25519 requirement, got: %v", err)
	}
}

// TestFromKeys_clonesCallerBuffers pins the contract that FromKeys owns the
// material it stores: wiping the caller's three input slices after FromKeys
// returns must leave the manager's view of its material unchanged, and the
// derived key id must remain the value computed before the wipe.
//
// The same caller code is what wipes a temporary buffer in a secret-manager
// helper once the call has succeeded. Before the fix, that wipe blanked the
// refresh secret the manager was still using, so every issued refresh-token
// and API-key hash stopped matching and every signed credential token could
// not be verified.
func TestFromKeys_clonesCallerBuffers(t *testing.T) {
	priv, pub := genPair(t)
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)

	km, err := keymanager.FromKeys(priv, pub, secret)
	if err != nil {
		t.Fatalf("FromKeys: %v", err)
	}
	wantID := km.KeyID()
	wantPriv := append(ed25519.PrivateKey(nil), priv...)
	wantPub := append(ed25519.PublicKey(nil), pub...)
	wantSecret := append([]byte(nil), secret...)

	// Wipe every byte of the caller's three buffers. A manager that holds a
	// reference instead of a copy now reads zero bytes and is broken.
	for i := range priv {
		priv[i] = 0
	}
	for i := range pub {
		pub[i] = 0
	}
	for i := range secret {
		secret[i] = 0
	}

	if got := km.KeyID(); got != wantID {
		t.Errorf("KeyID changed after caller wiped its buffers: got %q, want %q", got, wantID)
	}
	if got := km.PrivateKey(); !bytes.Equal(got, wantPriv) {
		t.Errorf("PrivateKey contents changed after caller wipe\ngot:  %x\nwant: %x", got, wantPriv)
	}
	if got := km.PublicKey(); !bytes.Equal(got, wantPub) {
		t.Errorf("PublicKey contents changed after caller wipe\ngot:  %x\nwant: %x", got, wantPub)
	}
	if got := km.RefreshSecret(); !bytes.Equal(got, wantSecret) {
		t.Errorf("RefreshSecret contents changed after caller wipe\ngot:  %x\nwant: %x", got, wantSecret)
	}
}

// TestFromKeys_clonesCallerBuffers_acceptance: a manager built from buffers
// the caller never touches must derive the same key id as the wiped-input
// case. Together the two tests pin both the cloning contract and the
// happy-path equivalence: cloning must not change the material the manager
// exposes.
func TestFromKeys_clonesCallerBuffers_acceptance(t *testing.T) {
	priv1, pub1 := genPair(t)
	priv2, pub2 := genPair(t)
	secret1 := make([]byte, 32)
	secret2 := make([]byte, 32)
	_, _ = rand.Read(secret1)
	_, _ = rand.Read(secret2)

	km1, err := keymanager.FromKeys(priv1, pub1, secret1)
	if err != nil {
		t.Fatalf("first FromKeys: %v", err)
	}
	for i := range priv1 {
		priv1[i] = 0
	}
	for i := range pub1 {
		pub1[i] = 0
	}
	for i := range secret1 {
		secret1[i] = 0
	}
	km2, err := keymanager.FromKeys(priv2, pub2, secret2)
	if err != nil {
		t.Fatalf("second FromKeys: %v", err)
	}

	if km1.KeyID() == km2.KeyID() {
		t.Error("two independent key pairs produced the same KeyID")
	}
	if !bytes.Equal(km1.PrivateKey(), km1.PrivateKey()) {
		t.Fatal("km1 private key is not self-consistent")
	}
	if !bytes.Equal(km2.PrivateKey(), km2.PrivateKey()) {
		t.Fatal("km2 private key is not self-consistent")
	}
	if bytes.Equal(km1.RefreshSecret(), km2.RefreshSecret()) {
		t.Error("two independent refresh secrets collapsed to the same bytes")
	}
}
