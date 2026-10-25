package recovery_test

import (
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/totp"
)

// ---- Recovery codes ---------------------------------------------------------

func TestVerifyRecoveryCode_AllMatch(t *testing.T) {
	mod := newTOTP(t, totp.Config{RecoveryCodeCount: 8})
	enr, err := mod.Enroll("alice@example.com")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	for i, c := range enr.RecoveryCodes {
		gotIdx, ok := mod.VerifyRecoveryCode(c, enr.RecoveryHashes)
		if !ok {
			t.Errorf("recovery code %d (%q) did not verify", i, c)
			continue
		}
		if gotIdx != i {
			t.Errorf("recovery code %d returned index %d", i, gotIdx)
		}
	}
}

func TestVerifyRecoveryCode_WrongCode(t *testing.T) {
	mod := newTOTP(t, totp.Config{RecoveryCodeCount: 4})
	enr, err := mod.Enroll("alice@example.com")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if _, ok := mod.VerifyRecoveryCode("AAAA1111-BBBB2222", enr.RecoveryHashes); ok {
		t.Error("a non-mint code verified as if it were in the list")
	}
	if _, ok := mod.VerifyRecoveryCode("", enr.RecoveryHashes); ok {
		t.Error("empty code verified")
	}
}

func TestVerifyRecoveryCode_Normalisation(t *testing.T) {
	mod := newTOTP(t, totp.Config{RecoveryCodeCount: 4})
	enr, err := mod.Enroll("alice@example.com")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	c := enr.RecoveryCodes[2]

	variants := []string{
		c,                               // as-is
		strings.ReplaceAll(c, "-", ""),  // no hyphen
		strings.ToUpper(c),              // uppercase (base32 letters)
		strings.ReplaceAll(c, "-", " "), // space instead of hyphen
		strings.ReplaceAll(strings.ToUpper(c), "-", " "),
	}
	for _, v := range variants {
		idx, ok := mod.VerifyRecoveryCode(v, enr.RecoveryHashes)
		if !ok || idx != 2 {
			t.Errorf("variant %q failed to verify (idx=%d ok=%v)", v, idx, ok)
		}
	}
}

func TestVerifyRecoveryCode_EmptyList(t *testing.T) {
	mod := newTOTP(t)
	if idx, ok := mod.VerifyRecoveryCode("ABCD1234-EFGH5678", nil); ok {
		t.Errorf("non-empty code matched an empty hash list (idx=%d)", idx)
	}
}

func TestHashRecoveryCode_MatchesEnrollmentHashes(t *testing.T) {
	mod := newTOTP(t)
	enr, err := mod.Enroll("alice@example.com")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	for i, c := range enr.RecoveryCodes {
		got, err := mod.HashRecoveryCode(c)
		if err != nil || got != enr.RecoveryHashes[i] {
			t.Errorf("HashRecoveryCode(%q) = %q, %v; want %q", c, got, err, enr.RecoveryHashes[i])
		}
	}
}

func TestHashRecoveryCode_Peppered(t *testing.T) {
	// Hashing the same code under two different refresh secrets must
	// produce different digests; otherwise the pepper is not applied.
	p1 := newFakeProvider(t)
	p2 := fakeProvider{keys: fakeKeys{secret: []byte(strings.Repeat("z", 32))}}
	m1, _ := totp.New(p1)
	m2, _ := totp.New(p2)
	h1, err1 := m1.HashRecoveryCode("ABCD1234-EFGH5678")
	h2, err2 := m2.HashRecoveryCode("ABCD1234-EFGH5678")
	if err1 != nil || err2 != nil {
		t.Fatalf("HashRecoveryCode: %v, %v", err1, err2)
	}
	if h1 == h2 {
		t.Error("hash is identical under different server secrets; HMAC pepper is not applied")
	}
}
