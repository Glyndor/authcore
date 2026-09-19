package field

// Round-trip and basic-shape tests for the field module. The package-internal
// test scope (package field rather than field_test) lets the suite import
// unexported helpers like buildAAD when needed. Same pattern as auth/credential
// and auth/totp.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/Glyndor/authcore"
)

// ---- test doubles -----------------------------------------------------------

type fakeKeys struct{ secret []byte }

func (fakeKeys) PrivateKey() ed25519.PrivateKey { return nil }
func (fakeKeys) PublicKey() ed25519.PublicKey   { return nil }
func (k fakeKeys) RefreshSecret() []byte        { return k.secret }
func (fakeKeys) KeyID() string                  { return "test" }

type fakeProvider struct{ keys authcore.Keys }

func (fakeProvider) Config() authcore.Config { return authcore.DefaultConfig() }
func (fakeProvider) Logger() authcore.Logger { return silentLogger{} }
func (p fakeProvider) Keys() authcore.Keys   { return p.keys }

type silentLogger struct{}

func (silentLogger) Debug(string, ...any) {}
func (silentLogger) Info(string, ...any)  {}
func (silentLogger) Warn(string, ...any)  {}
func (silentLogger) Error(string, ...any) {}

func newFakeProvider(tb testing.TB) fakeProvider {
	tb.Helper()
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		tb.Fatalf("generate test HKAC secret: %v", err)
	}
	return fakeProvider{keys: fakeKeys{secret: secret}}
}

// newFld builds a Field for tests. The provider is fresh per call so two
// modules share a key only when the caller explicitly hands them the
// same provider.
func newFld(tb testing.TB, context string) *Field {
	tb.Helper()
	mod, err := New(newFakeProvider(tb), Config{Context: context})
	if err != nil {
		tb.Fatalf("field.New: %v", err)
	}
	return mod
}

// ---- Name / module wiring ---------------------------------------------------

func TestName(t *testing.T) {
	if got := newFld(t, "email").Name(); got != "field" {
		t.Errorf("Name() = %q, want field", got)
	}
}

func TestNew_SatisfiesModule(t *testing.T) {
	var m authcore.Module = newFld(t, "email")
	if m.Name() != "field" {
		t.Errorf("module Name() = %q, want field", m.Name())
	}
}

// ---- Round trip -------------------------------------------------------------

// TestRoundTrip_HappyPath is the basic Encrypt/Decrypt cycle on a normal
// string. Removing Decrypt or Encrypt makes the test fail.
func TestRoundTrip_HappyPath(t *testing.T) {
	f := newFld(t, "email")
	ct, err := f.Encrypt("alice@example.com")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	pt, err := f.Decrypt(ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if pt != "alice@example.com" {
		t.Errorf("round trip = %q, want alice@example.com", pt)
	}
}

// TestRoundTrip_EmptyString covers the empty plaintext. Empty is a
// legitimate value (an optional field that the user did not fill) and
// must round trip like any other value.
func TestRoundTrip_EmptyString(t *testing.T) {
	f := newFld(t, "email")
	ct, err := f.Encrypt("")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	pt, err := f.Decrypt(ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if pt != "" {
		t.Errorf("empty round trip = %q, want empty", pt)
	}
}

// TestRoundTrip_LongString covers a plaintext longer than the GCM
// internals step on. A long string is a stress test of the nonce,
// AAD, and seal buffers and must round trip cleanly.
func TestRoundTrip_LongString(t *testing.T) {
	f := newFld(t, "email")
	plain := strings.Repeat("a long plaintext ", 1000) // ~18 KB
	ct, err := f.Encrypt(plain)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	pt, err := f.Decrypt(ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if pt != plain {
		t.Error("long round trip mismatch")
	}
}

// TestRoundTrip_InvalidUTF8 covers a plaintext that is not valid UTF-8.
// Decrypt hands the bytes back to the caller as-is, so an arbitrary
// byte sequence must survive the round trip untouched.
func TestRoundTrip_InvalidUTF8(t *testing.T) {
	f := newFld(t, "email")
	plain := string([]byte{0x00, 0xC3, 0x28, 0xFE, 0xFF, 0x80, 0x81, 0x82, 0xA0, 0xA1})
	ct, err := f.Encrypt(plain)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	pt, err := f.Decrypt(ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if pt != plain {
		t.Errorf("invalid-UTF8 round trip = %q, want %q", pt, plain)
	}
}

// ---- Nonce uniqueness -------------------------------------------------------

// TestEncrypt_DifferentCiphertextsForSamePlaintext is the nonce test.
// If Encrypt ever derives the nonce from the plaintext, the two
// ciphertexts will match; here they must not. Both must also still
// decrypt back to the same plaintext.
func TestEncrypt_DifferentCiphertextsForSamePlaintext(t *testing.T) {
	f := newFld(t, "email")
	const plain = "alice@example.com"

	ct1, err := f.Encrypt(plain)
	if err != nil {
		t.Fatalf("Encrypt #1: %v", err)
	}
	ct2, err := f.Encrypt(plain)
	if err != nil {
		t.Fatalf("Encrypt #2: %v", err)
	}
	if ct1 == ct2 {
		t.Fatal("two Encrypt calls of the same plaintext returned the same ciphertext; nonce is being derived or reused")
	}

	pt1, err := f.Decrypt(ct1)
	if err != nil {
		t.Fatalf("Decrypt #1: %v", err)
	}
	pt2, err := f.Decrypt(ct2)
	if err != nil {
		t.Fatalf("Decrypt #2: %v", err)
	}
	if pt1 != plain || pt2 != plain {
		t.Errorf("round trip mismatch: %q / %q, want %q", pt1, pt2, plain)
	}
}

// ---- Decrypt failure modes --------------------------------------------------

// TestDecrypt_TamperedNonce flips one byte in the nonce region (the
// first 12 bytes of the decoded ciphertext) and asserts the result
// is ErrDecrypt, not a panic. This is the half of the bit-flip test
// that hits the nonce.
func TestDecrypt_TamperedNonce(t *testing.T) {
	f := newFld(t, "email")
	ct, err := f.Encrypt("alice@example.com")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	raw, err := base64.RawStdEncoding.DecodeString(ct)
	if err != nil {
		t.Fatalf("decode ciphertext: %v", err)
	}
	// Flip one bit in byte 0 (well inside the 12-byte nonce).
	raw[0] ^= 0x01
	tampered := base64.RawStdEncoding.EncodeToString(raw)

	if _, err := f.Decrypt(tampered); !errors.Is(err, ErrDecrypt) {
		t.Errorf("Decrypt with tampered nonce: got %v, want ErrDecrypt", err)
	}
}

// TestDecrypt_TamperedSealed flips one byte in the sealed region
// (past the 12-byte nonce) and asserts ErrDecrypt. AAD binding would
// also be caught here if the byte happened to be in the tag; this
// is the half of the bit-flip test that hits the sealed payload.
func TestDecrypt_TamperedSealed(t *testing.T) {
	f := newFld(t, "email")
	ct, err := f.Encrypt("alice@example.com")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	raw, err := base64.RawStdEncoding.DecodeString(ct)
	if err != nil {
		t.Fatalf("decode ciphertext: %v", err)
	}
	// Flip one byte past the nonce, well into the sealed payload.
	raw[nonceLen+2] ^= 0xFF
	tampered := base64.RawStdEncoding.EncodeToString(raw)

	if _, err := f.Decrypt(tampered); !errors.Is(err, ErrDecrypt) {
		t.Errorf("Decrypt with tampered sealed: got %v, want ErrDecrypt", err)
	}
}

// TestDecrypt_TruncatedBelowNonce covers input shorter than the
// 12-byte nonce. A short row is corrupt data: it must return ErrDecrypt
// and must not panic or index out of range. The function checks
// length before slicing.
func TestDecrypt_TruncatedBelowNonce(t *testing.T) {
	f := newFld(t, "email")
	// 5 bytes, base64-encoded to a 7-character string.
	short := base64.RawStdEncoding.EncodeToString([]byte{1, 2, 3, 4, 5})
	if _, err := f.Decrypt(short); !errors.Is(err, ErrDecrypt) {
		t.Errorf("Decrypt(short): got %v, want ErrDecrypt", err)
	}
}

// TestDecrypt_EmptyString covers the empty string. It is not valid
// base64 for any non-empty payload and must return ErrDecrypt.
func TestDecrypt_EmptyString(t *testing.T) {
	f := newFld(t, "email")
	if _, err := f.Decrypt(""); !errors.Is(err, ErrDecrypt) {
		t.Errorf("Decrypt(\"\"): got %v, want ErrDecrypt", err)
	}
}

// TestDecrypt_InvalidBase64 covers input that is not valid base64.
// Decrypt must answer ErrDecrypt, not a panic. The base64 decoder
// itself does not panic on bad input; this pins that.
func TestDecrypt_InvalidBase64(t *testing.T) {
	f := newFld(t, "email")
	// RawStdEncoding rejects '='; a long-enough string of invalid
	// bytes is enough to trigger the decoder error path.
	bad := "!!!!notbase64!!!!"
	if _, err := f.Decrypt(bad); !errors.Is(err, ErrDecrypt) {
		t.Errorf("Decrypt(invalid base64): got %v, want ErrDecrypt", err)
	}
}
