package seal

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func newSealer(t *testing.T, key byte, context string) *Sealer {
	t.Helper()
	s, err := New(bytes.Repeat([]byte{key}, 32), []byte(context))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func TestNew_refusesAKeyAESCannotUse(t *testing.T) {
	if _, err := New([]byte("short"), nil); err == nil {
		t.Fatal("New accepted a 5-byte key")
	}
}

func TestSealOpen_roundTripsWithAFreshNonceEachTime(t *testing.T) {
	s := newSealer(t, 1, "email")
	a, err := s.Seal("alice@example.com")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	b, err := s.Seal("alice@example.com")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if a == b {
		t.Error("two seals of one plaintext were identical: the nonce repeated")
	}
	for _, ct := range []string{a, b} {
		got, err := s.Open(ct)
		if err != nil || got != "alice@example.com" {
			t.Errorf("Open = %q, %v; want the plaintext", got, err)
		}
	}
}

func TestOpen_refusesAnotherContextAnotherKeyAndTampering(t *testing.T) {
	s := newSealer(t, 1, "email")
	ct, err := s.Seal("alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newSealer(t, 1, "phone").Open(ct); !errors.Is(err, ErrOpen) {
		t.Errorf("another context: %v, want ErrOpen", err)
	}
	if _, err := newSealer(t, 2, "email").Open(ct); !errors.Is(err, ErrOpen) {
		t.Errorf("another key: %v, want ErrOpen", err)
	}
	raw, _ := base64.RawStdEncoding.DecodeString(ct)
	raw[NonceLen+2] ^= 0xFF
	if _, err := s.Open(base64.RawStdEncoding.EncodeToString(raw)); !errors.Is(err, ErrOpen) {
		t.Errorf("tampered payload: %v, want ErrOpen", err)
	}
}

func TestOpen_refusesMalformedInputWithoutPanicking(t *testing.T) {
	s := newSealer(t, 1, "email")
	ct, err := s.Seal("alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	for name, in := range map[string]string{
		"empty":                "",
		"not base64":           "!!!!",
		"shorter than a nonce": base64.RawStdEncoding.EncodeToString(make([]byte, NonceLen-1)),
		"no room for a tag":    base64.RawStdEncoding.EncodeToString(make([]byte, NonceLen+tagLen-1)),
		"another spelling":     ct[:len(ct)/2] + "\n" + ct[len(ct)/2:],
		"padded":               ct + strings.Repeat("=", 2),
	} {
		if _, err := s.Open(in); !errors.Is(err, ErrOpen) {
			t.Errorf("%s: %v, want ErrOpen", name, err)
		}
	}
}
