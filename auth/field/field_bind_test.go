package field

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/Glyndor/authcore"
)

// sharedProvider returns a provider whose keys are pinned so two
// Field instances share the same root secret. Used to assert that
// "the same value, two different contexts" is separated by Context
// alone, without the test also having to fight different secrets.
func sharedProvider(tb testing.TB) authcore.Provider {
	tb.Helper()
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		tb.Fatalf("generate shared secret: %v", err)
	}
	return sharedProviderWith(secret)
}

type sharedKeys struct{ secret []byte }

func (sharedKeys) PrivateKey() ed25519.PrivateKey { return nil }

func (sharedKeys) PublicKey() ed25519.PublicKey { return nil }

func (k sharedKeys) RefreshSecret() []byte { return k.secret }

func (sharedKeys) KeyID() string { return "test" }

// sharedProviderWith wraps a fixed secret in a Provider that satisfies
// the authcore.Provider interface used by the field module's tests.
func sharedProviderWith(secret []byte) authcore.Provider {
	return &testProvider{keys: sharedKeys{secret: secret}}
}

type testProvider struct{ keys sharedKeys }

func (*testProvider) Config() authcore.Config { return authcore.DefaultConfig() }

func (*testProvider) Logger() authcore.Logger { return silentLogger{} }

func (p *testProvider) Keys() authcore.Keys { return p.keys }

// ---- Context binding (AAD) --------------------------------------------------

// TestCrossContext_DecryptFailsAcrossContexts is the AAD binding
// test. A ciphertext produced under "email" must not decrypt under
// a module built with "phone", because the AAD differs and GCM
// authentication fails. The test passes the ciphertext from the
// email module to the phone module, which is the exact swap a
// confused-caller bug would do.
func TestCrossContext_DecryptFailsAcrossContexts(t *testing.T) {
	p := sharedProvider(t)
	email, err := New(p, Config{Context: "email"})
	if err != nil {
		t.Fatalf("New email: %v", err)
	}
	phone, err := New(p, Config{Context: "phone"})
	if err != nil {
		t.Fatalf("New phone: %v", err)
	}

	ct, err := email.Encrypt("alice@example.com")
	if err != nil {
		t.Fatalf("email.Encrypt: %v", err)
	}
	if _, err := phone.Decrypt(ct); !errors.Is(err, ErrDecrypt) {
		t.Errorf("phone.Decrypt(email ct): got %v, want ErrDecrypt", err)
	}
}

// TestCrossContext_DifferentCiphertextsForSamePlaintext asserts the
// same swap from the other side: two modules with different contexts
// must produce different ciphertexts for the same plaintext, and
// neither can read the other's. Context is fed to GCM as additional
// authenticated data, so a ciphertext moved from one column to
// another must fail to open rather than decrypt under the wrong
// field's name.
func TestCrossContext_DifferentCiphertextsForSamePlaintext(t *testing.T) {
	p := sharedProvider(t)
	email, _ := New(p, Config{Context: "email"})
	phone, _ := New(p, Config{Context: "phone"})

	const plain = "alice@example.com"
	ctEmail, err := email.Encrypt(plain)
	if err != nil {
		t.Fatalf("email.Encrypt: %v", err)
	}
	ctPhone, err := phone.Encrypt(plain)
	if err != nil {
		t.Fatalf("phone.Encrypt: %v", err)
	}
	if ctEmail == ctPhone {
		t.Fatal("two modules with different contexts produced the same ciphertext for the same plaintext")
	}

	if _, err := phone.Decrypt(ctEmail); !errors.Is(err, ErrDecrypt) {
		t.Errorf("phone.Decrypt(email ct): got %v, want ErrDecrypt", err)
	}
	if _, err := email.Decrypt(ctPhone); !errors.Is(err, ErrDecrypt) {
		t.Errorf("email.Decrypt(phone ct): got %v, want ErrDecrypt", err)
	}
}

// ---- Context binding (blind index) ------------------------------------------

// TestBlindIndex_DeterministicAcrossCalls: BlindIndex of the same
// value under the same module must be stable. BlindIndex returns a
// string and an error; the happy path has no error and the digest is
// 32 bytes hex-encoded.
func TestBlindIndex_DeterministicAcrossCalls(t *testing.T) {
	f := newFld(t, "email")
	a, err := f.BlindIndex("alice@example.com")
	if err != nil {
		t.Fatalf("BlindIndex: %v", err)
	}
	b, err := f.BlindIndex("alice@example.com")
	if err != nil {
		t.Fatalf("BlindIndex: %v", err)
	}
	if a != b {
		t.Errorf("BlindIndex not deterministic: %s vs %s", a, b)
	}
	if len(a) != 64 {
		t.Errorf("BlindIndex length = %d, want 64 (hex SHA-256)", len(a))
	}
}

// TestBlindIndex_DeterministicAcrossModules: two modules built from
// the same provider and context must produce the same blind index
// for the same value. This is what makes "store index, look up by
// index" work across restarts and across instances.
func TestBlindIndex_DeterministicAcrossModules(t *testing.T) {
	p := sharedProvider(t)
	a, _ := New(p, Config{Context: "email"})
	b, _ := New(p, Config{Context: "email"})

	idxA, err := a.BlindIndex("alice@example.com")
	if err != nil {
		t.Fatalf("BlindIndex: %v", err)
	}
	idxB, err := b.BlindIndex("alice@example.com")
	if err != nil {
		t.Fatalf("BlindIndex: %v", err)
	}
	if idxA != idxB {
		t.Errorf("BlindIndex across same-config modules differs: %s vs %s", idxA, idxB)
	}
}

// TestBlindIndex_DiffersAcrossContexts: the same value under two
// different contexts must produce different indexes. The Context is
// bound into the HMAC input, so "email" and "phone" cannot share an
// index space.
func TestBlindIndex_DiffersAcrossContexts(t *testing.T) {
	p := sharedProvider(t)
	email, _ := New(p, Config{Context: "email"})
	phone, _ := New(p, Config{Context: "phone"})

	const value = "alice@example.com"
	idxEmail, err := email.BlindIndex(value)
	if err != nil {
		t.Fatalf("email.BlindIndex: %v", err)
	}
	idxPhone, err := phone.BlindIndex(value)
	if err != nil {
		t.Fatalf("phone.BlindIndex: %v", err)
	}
	if idxEmail == idxPhone {
		t.Errorf("BlindIndex of %q under different contexts matched", value)
	}
}

// ---- Length-prefix non-collision --------------------------------------------

// TestBlindIndex_DifferentValuesDifferentIndexes is the obvious
// "different input, different output" check. The HMAC is not
// guaranteed to be collision-free in principle, but for the
// 32-byte hex output a near-collision from two short strings is
// not reachable by a test seed.
func TestBlindIndex_DifferentValuesDifferentIndexes(t *testing.T) {
	f := newFld(t, "email")
	idxAlice, err := f.BlindIndex("alice@example.com")
	if err != nil {
		t.Fatalf("BlindIndex: %v", err)
	}
	idxBob, err := f.BlindIndex("bob@example.com")
	if err != nil {
		t.Fatalf("BlindIndex: %v", err)
	}
	if idxAlice == idxBob {
		t.Error("different values produced the same blind index")
	}
}
