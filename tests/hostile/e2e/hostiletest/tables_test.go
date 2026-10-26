package hostiletest_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/credential"
	"github.com/Glyndor/authcore/auth/totp"
	"github.com/Glyndor/authcore/tests/hostile/e2e/hostiletest"
)

func TestTokenTable_redeemIsSingleUse(t *testing.T) {
	e := hostiletest.NewEnv(t)
	c := e.Credential(t, credential.DefaultConfig())
	issued, err := c.Issue("reset", "alice")
	if err != nil {
		t.Fatal(err)
	}
	tt := hostiletest.NewTokenTable()
	if err := tt.Redeem(c, "reset", "alice", issued.Token); !errors.Is(err, hostiletest.ErrNoRow) {
		t.Fatalf("empty table = %v, want ErrNoRow", err)
	}
	tt.Put("alice", hostiletest.TokenRow{Hash: issued.Hash, IssuedAt: time.Now()})
	if err := tt.Redeem(c, "other", "alice", issued.Token); !errors.Is(err, credential.ErrInvalidCredential) {
		t.Fatalf("wrong purpose = %v, want ErrInvalidCredential", err)
	}
	if err := tt.Redeem(c, "reset", "alice", issued.Token); err != nil {
		t.Fatalf("first redemption: %v", err)
	}
	if err := tt.Redeem(c, "reset", "alice", issued.Token); !errors.Is(err, hostiletest.ErrNoRow) {
		t.Errorf("second redemption = %v, want ErrNoRow", err)
	}
	if tt.Len() != 0 {
		t.Error("a consumed row is still pending")
	}
	if tt.Consume("alice", "x") {
		t.Error("consume on a missing row succeeded")
	}
	tt.Put("bob", hostiletest.TokenRow{Hash: "h"})
	if tt.Consume("bob", "other") {
		t.Error("consume with a different hash succeeded")
	}
}

func TestAccount_recorderAndRecoveryAreAtomicAndSingleUse(t *testing.T) {
	e := hostiletest.NewEnv(t)
	m := e.TOTP(t, totp.Config{RecoveryCodeCount: 3})
	acc := hostiletest.Enroll(t, m, "alice@example.com")
	if acc.Remaining() != 3 || len(acc.Codes) != 3 {
		t.Fatalf("enrolled with %d hashes and %d codes", acc.Remaining(), len(acc.Codes))
	}
	if err := acc.RecordIfNewer(context.Background(), 5); err != nil {
		t.Fatal(err)
	}
	if err := acc.RecordIfNewer(context.Background(), 5); !errors.Is(err, totp.ErrCodeReused) {
		t.Errorf("same step twice = %v, want ErrCodeReused", err)
	}
	if acc.LastStep() != 5 {
		t.Errorf("last step = %d, want 5", acc.LastStep())
	}
	if !acc.UseRecovery(m, acc.Codes[1]) || acc.Remaining() != 2 {
		t.Error("a recovery code did not redeem once")
	}
	if acc.UseRecovery(m, acc.Codes[1]) {
		t.Error("a recovery code redeemed twice")
	}
	if acc.UseRecovery(m, "AAAAAAAA-AAAAAAAA") {
		t.Error("a code nobody holds redeemed")
	}
}

func TestCodeAt_agreesWithTheModuleAndStepHelpers(t *testing.T) {
	e := hostiletest.NewEnv(t)
	m := e.TOTP(t, totp.Config{})
	acc := hostiletest.Enroll(t, m, "alice@example.com")
	hostiletest.AtStableStep(t, func(step uint64) string {
		if err := m.Verify(context.Background(), acc.Secret, hostiletest.CodeAt(t, acc.Secret, step), acc); err != nil {
			return "current code refused: " + err.Error()
		}
		return ""
	})
}

func TestAtStableStep_failsWhenTheBodyReports(t *testing.T) {
	if !fails(func(tb testing.TB) { hostiletest.AtStableStep(tb, func(uint64) string { return "broken" }) }) {
		t.Error("a failure message did not fail the test")
	}
}

func TestUsers_uniqueIndex(t *testing.T) {
	u := hostiletest.NewUsers()
	if id, err := u.Insert("ct1", "idx"); err != nil || id != 1 {
		t.Fatalf("first insert = %d, %v", id, err)
	}
	if _, err := u.Insert("ct2", "idx"); !errors.Is(err, hostiletest.ErrDuplicate) {
		t.Errorf("duplicate index = %v, want ErrDuplicate", err)
	}
	if row, ok := u.FindByIdx("idx"); !ok || row.EmailCT != "ct1" {
		t.Errorf("lookup = %+v, %v", row, ok)
	}
	if _, ok := u.FindByIdx("nope"); ok {
		t.Error("lookup of an absent index found a row")
	}
	if u.Len() != 1 || len(u.Rows()) != 1 {
		t.Error("table does not hold exactly one row")
	}
}

// The oracle's own hash against the published vectors: RFC 4226 appendix D for
// the codes, RFC 2202 for HMAC-SHA1 with a short key and with a key longer than
// the block (hashed first).
func TestCodeAt_matchesTheRFCVectors(t *testing.T) {
	const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" // base32 of "12345678901234567890"
	want := []string{"755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"}
	for counter, code := range want {
		if got := hostiletest.CodeAt(t, secret, uint64(counter)); got != code {
			t.Errorf("counter %d = %s, want %s", counter, got, code)
		}
	}
	short := hostiletest.HMACSHA1(bytes.Repeat([]byte{0x0b}, 20), []byte("Hi There"))
	if got := hex.EncodeToString(short); got != "b617318655057264e28bc0b6fb378c8ef146be00" {
		t.Errorf("HMAC-SHA1 with a short key = %s", got)
	}
	long := hostiletest.HMACSHA1(bytes.Repeat([]byte{0xaa}, 80), []byte("Test Using Larger Than Block-Size Key - Hash Key First"))
	if got := hex.EncodeToString(long); got != "aa4ae5e15272d00e95705637ce8a3b55ed402112" {
		t.Errorf("HMAC-SHA1 with a long key = %s", got)
	}
}
