package field

// Tests for the Context binding into both the AES AAD and the blind
// index, the length-prefixed non-collision guarantee, and the
// cross-context uniqueness of ciphertexts and indexes. The shape
// mirrors auth/credential/credential_bind_test.go.

import (
	"bytes"
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
func (sharedKeys) PublicKey() ed25519.PublicKey   { return nil }
func (k sharedKeys) RefreshSecret() []byte        { return k.secret }
func (sharedKeys) KeyID() string                  { return "test" }

// sharedProviderWith wraps a fixed secret in a Provider that satisfies
// the authcore.Provider interface used by the field module's tests.
func sharedProviderWith(secret []byte) authcore.Provider {
	return &testProvider{keys: sharedKeys{secret: secret}}
}

type testProvider struct{ keys sharedKeys }

func (*testProvider) Config() authcore.Config { return authcore.DefaultConfig() }
func (*testProvider) Logger() authcore.Logger { return silentLogger{} }
func (p *testProvider) Keys() authcore.Keys   { return p.keys }

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
// string and no error, since HMAC-SHA256 over a fixed key cannot fail.
func TestBlindIndex_DeterministicAcrossCalls(t *testing.T) {
	f := newFld(t, "email")
	a := f.BlindIndex("alice@example.com")
	b := f.BlindIndex("alice@example.com")
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

	idxA := a.BlindIndex("alice@example.com")
	idxB := b.BlindIndex("alice@example.com")
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
	if email.BlindIndex(value) == phone.BlindIndex(value) {
		t.Errorf("BlindIndex of %q under different contexts matched", value)
	}
}

// ---- Length-prefix non-collision --------------------------------------------

// TestLengthPrefix_NoCollisionBetweenAdjacentFields is the structural
// guarantee that the length prefix prevents ("a", "bc") from colliding
// with ("ab", "c"). The cases are chosen so a separator-byte
// implementation would collide and the length-prefixed one does not.
// "a||bc" = 0x61 0x62 0x63; "ab||c" = 0x61 0x62 0x63. A separator
// would fold them; the length prefix does not.
func TestLengthPrefix_NoCollisionBetweenAdjacentFields(t *testing.T) {
	p := sharedProvider(t)
	// One context, two different splits of the same byte sequence.
	a, _ := New(p, Config{Context: "a"})
	ab, _ := New(p, Config{Context: "ab"})

	const value = "c" // the "value" is the same, only the context splits
	// a + "bc" vs "ab" + "c": the bytes inside the HMAC are the same,
	// but the framing differs. A separator would collapse them; a
	// length prefix does not.
	if a.BlindIndex("bc") == ab.BlindIndex(value) {
		t.Error("length prefix collision: BlindIndex(\"bc\") under context \"a\" matched BlindIndex(\"c\") under context \"ab\"")
	}
}

// TestLengthPrefix_NoCollisionBetweenContextAndValue is the broader
// version of the same guarantee. We choose a single context "email"
// and a single value "user@x", and another arrangement where the
// combined bytes are the same but the boundary is in a different
// place. A length prefix keeps them apart; a separator would not.
func TestLengthPrefix_NoCollisionBetweenContextAndValue(t *testing.T) {
	p := sharedProvider(t)
	// context "a", value "bc" -> bytes a, b, c
	a, _ := New(p, Config{Context: "a"})
	// context "ab", value "c" -> bytes a, b, c
	ab, _ := New(p, Config{Context: "ab"})

	if a.BlindIndex("bc") == ab.BlindIndex("c") {
		t.Error("length prefix collision: (\"a\",\"bc\") matched (\"ab\",\"c\")")
	}
}

// TestLengthPrefix_NoCollisionSameContextSameValue is the trivial
// sanity check: the same value under the same context must produce
// the same index (already covered above, but listed here for the
// "all four quadrants of the collision matrix" symmetry).
func TestLengthPrefix_NoCollisionSameContextSameValue(t *testing.T) {
	f := newFld(t, "email")
	if f.BlindIndex("alice@example.com") != f.BlindIndex("alice@example.com") {
		t.Error("same context, same value produced different indexes")
	}
}

// TestBlindIndex_DifferentValuesDifferentIndexes is the obvious
// "different input, different output" check. The HMAC is not
// guaranteed to be collision-free in principle, but for the
// 32-byte hex output a near-collision from two short strings is
// not reachable by a test seed.
func TestBlindIndex_DifferentValuesDifferentIndexes(t *testing.T) {
	f := newFld(t, "email")
	if f.BlindIndex("alice@example.com") == f.BlindIndex("bob@example.com") {
		t.Error("different values produced the same blind index")
	}
}

// TestDeriveKey_SeparatesTheTwoKeysFromEachOtherAndFromTheMaster pins key
// separation, which no behavioural test can see.
//
// Encrypt, Decrypt and BlindIndex all keep working if deriveKey is removed
// and Keys().RefreshSecret() is used directly for both the AES key and the
// index key. Round trips still round trip and indexes still match, so the
// whole suite stays green while one secret is doing three jobs and a
// weakness in any one construction reaches the others.
//
// This is the assertion that goes red instead.
func TestDeriveKey_SeparatesTheTwoKeysFromEachOtherAndFromTheMaster(t *testing.T) {
	t.Parallel()

	master := newFakeProvider(t).Keys().RefreshSecret()

	encKey, err := deriveKey(master, encKeyInfo)
	if err != nil {
		t.Fatalf("deriveKey(encKeyInfo): %v", err)
	}
	idxKey, err := deriveKey(master, idxKeyInfo)
	if err != nil {
		t.Fatalf("deriveKey(idxKeyInfo): %v", err)
	}

	for name, key := range map[string][]byte{"encKey": encKey, "idxKey": idxKey} {
		if len(key) != keyLen {
			t.Errorf("%s is %d bytes, want %d", name, len(key), keyLen)
		}
		if bytes.Equal(key, master) {
			t.Errorf("%s is the master secret verbatim: the derivation was skipped", name)
		}
	}
	if bytes.Equal(encKey, idxKey) {
		t.Error("encKey and idxKey are the same value: both info labels derive one key")
	}

	// Derivation must be deterministic, or a restart would lose every row.
	again, err := deriveKey(master, encKeyInfo)
	if err != nil {
		t.Fatalf("deriveKey again: %v", err)
	}
	if !bytes.Equal(encKey, again) {
		t.Error("deriveKey is not deterministic: existing ciphertexts would not decrypt after a restart")
	}
}
