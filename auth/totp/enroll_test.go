package totp

import (
	"encoding/base32"
	"strings"
	"testing"
)

// ---- Enroll -----------------------------------------------------------------

func TestEnroll_UniqueSecretsAndCodes(t *testing.T) {
	mod := newTOTP(t, Config{Issuer: "Acme", RecoveryCodeCount: 5})
	a, err := mod.Enroll("alice@example.com")
	if err != nil {
		t.Fatalf("first Enroll: %v", err)
	}
	b, err := mod.Enroll("alice@example.com")
	if err != nil {
		t.Fatalf("second Enroll: %v", err)
	}
	if a.Secret == b.Secret {
		t.Error("two Enroll calls produced the same secret")
	}
	if len(a.RecoveryCodes) != 5 || len(b.RecoveryCodes) != 5 {
		t.Fatalf("RecoveryCodes length = %d and %d, want 5", len(a.RecoveryCodes), len(b.RecoveryCodes))
	}
	for i := range a.RecoveryCodes {
		if a.RecoveryCodes[i] == b.RecoveryCodes[i] {
			t.Errorf("recovery code %d matched between enrollments", i)
		}
	}
}

func TestEnroll_SecretShape(t *testing.T) {
	mod := newTOTP(t)
	enr, err := mod.Enroll("alice@example.com")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if len(enr.Secret) != 32 {
		t.Errorf("secret length = %d, want 32 (20 bytes base32 no padding)", len(enr.Secret))
	}
	if _, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(enr.Secret); err != nil {
		t.Errorf("secret is not valid base32: %v", err)
	}
}

func TestEnroll_RecoveryCodesShape(t *testing.T) {
	mod := newTOTP(t, Config{RecoveryCodeCount: 8})
	enr, err := mod.Enroll("alice@example.com")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if len(enr.RecoveryCodes) != 8 || len(enr.RecoveryHashes) != 8 {
		t.Fatalf("recovery slice length = %d/%d, want 8", len(enr.RecoveryCodes), len(enr.RecoveryHashes))
	}
	for i, c := range enr.RecoveryCodes {
		// "XXXXXXXX-XXXXXXXX" -> 8 + 1 + 8 = 17 chars, base32 only.
		if len(c) != 17 {
			t.Errorf("recovery code %d has length %d, want 17", i, len(c))
		}
		if c[8] != '-' {
			t.Errorf("recovery code %d missing hyphen at position 8: %q", i, c)
		}
		plain := strings.ReplaceAll(c, "-", "")
		if _, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(plain); err != nil {
			t.Errorf("recovery code %d not valid base32: %v", i, err)
		}
		// Hash must be a hex-encoded HMAC-SHA256: 64 lowercase hex chars.
		if len(enr.RecoveryHashes[i]) != 64 {
			t.Errorf("recovery hash %d has length %d, want 64", i, len(enr.RecoveryHashes[i]))
		}
	}
}
