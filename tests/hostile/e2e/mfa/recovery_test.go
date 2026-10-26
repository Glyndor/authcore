package mfa

import (
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Glyndor/authcore/auth/totp"
	"github.com/Glyndor/authcore/tests/hostile/e2e/hostiletest"
)

// Each recovery code works once; the printout shrinks by one per use; spelling
// variants of a spent code are the same spent code.
func TestE2E_MFA_recoveryCodesAreSingleUseWhateverTheSpelling(t *testing.T) {
	m := newModule(t, totp.Config{RecoveryCodeCount: 5})
	acc := hostiletest.Enroll(t, m, "alice@example.com")
	code := acc.Codes[2]
	variants := []string{
		code, strings.ToLower(code), strings.ReplaceAll(code, "-", ""),
		strings.ReplaceAll(code, "-", " "), " " + code, // surrounding space is not a separator
	}
	if !acc.UseRecovery(m, variants[0]) || acc.Remaining() != 4 {
		t.Fatal("the first use did not redeem")
	}
	for _, v := range variants {
		if acc.UseRecovery(m, v) {
			t.Errorf("spelling %q of a spent code redeemed", v)
		}
	}
	if acc.Remaining() != 4 {
		t.Errorf("remaining = %d after refused attempts, want 4", acc.Remaining())
	}
	for i, c := range acc.Codes {
		want := i != 2
		if got := acc.UseRecovery(m, c); got != want {
			t.Errorf("code %d redeemed = %v, want %v", i, got, want)
		}
	}
	if acc.Remaining() != 0 {
		t.Errorf("remaining = %d after every code was used, want 0", acc.Remaining())
	}
}

// The same code typed the way a person types it redeems, whichever spelling:
// the printout is read off paper.
func TestE2E_MFA_everySpellingOfAFreshRecoveryCodeRedeems(t *testing.T) {
	m := newModule(t, totp.Config{})
	acc := hostiletest.Enroll(t, m, "alice@example.com")
	for i, spell := range []func(string) string{
		strings.ToLower, strings.ToUpper, func(c string) string { return strings.ReplaceAll(c, "-", "") },
		func(c string) string { return strings.ReplaceAll(strings.ToLower(c), "-", " ") },
	} {
		code := acc.Codes[i]
		if !acc.UseRecovery(m, spell(code)) {
			t.Errorf("spelling %d of a fresh code (%q) did not redeem", i, spell(code))
		}
	}
	if acc.Remaining() != len(acc.Codes)-4 {
		t.Errorf("remaining = %d, want %d", acc.Remaining(), len(acc.Codes)-4)
	}
}

// A recovery code belongs to its account's list: it does not open another
// account, a TOTP code is not a recovery code, and a recovery code is not a
// TOTP code.
func TestE2E_MFA_recoveryCodesAndCodesDoNotCrossAccountsOrKinds(t *testing.T) {
	m := newModule(t, totp.Config{})
	a := hostiletest.Enroll(t, m, "a@example.com")
	b := hostiletest.Enroll(t, m, "b@example.com")

	for _, c := range a.Codes {
		if b.UseRecovery(m, c) {
			t.Fatalf("A's recovery code %q opened B", c)
		}
	}
	if b.Remaining() != len(b.Codes) {
		t.Error("attempts on B consumed B's hashes")
	}
	hostiletest.AtStableStep(t, func(step uint64) string {
		if a.UseRecovery(m, hostiletest.CodeAt(t, a.Secret, step)) {
			return "a TOTP code redeemed as a recovery code"
		}
		return ""
	})
	if err := m.Verify(ctx, a.Secret, a.Codes[0], a); err == nil {
		t.Error("a recovery code accepted as a TOTP code")
	}
	if a.Remaining() != len(a.Codes) || a.LastStep() != 0 {
		t.Error("crossing the kinds consumed something")
	}
	// Another deployment's module does not recognise this deployment's codes.
	foreign := newModule(t, totp.Config{})
	if _, ok := foreign.VerifyRecoveryCode(a.Codes[0], ownHashes(t, m, a)); ok {
		t.Error("a module with another secret matched this deployment's hashes")
	}
}

// ownHashes recomputes the stored hashes of an account's printout.
func ownHashes(t *testing.T, m *totp.TOTP, a *hostiletest.Account) []string {
	t.Helper()
	out := make([]string, len(a.Codes))
	for i, c := range a.Codes {
		h, err := m.HashRecoveryCode(c)
		if err != nil {
			t.Fatal(err)
		}
		out[i] = h
	}
	return out
}

// Many requests present one recovery code at once, in four spellings: exactly
// one is accepted and exactly one hash is gone.
func TestE2E_MFA_concurrentRecoveryRedemptionYieldsOneWinner(t *testing.T) {
	m := newModule(t, totp.Config{RecoveryCodeCount: 4})
	acc := hostiletest.Enroll(t, m, "alice@example.com")
	code := acc.Codes[1]
	spellings := []string{code, strings.ToLower(code), strings.ReplaceAll(code, "-", ""), strings.ReplaceAll(code, "-", " ")}

	const requests = 64
	var (
		wg      sync.WaitGroup
		start   = make(chan struct{})
		winners atomic.Int64
	)
	for i := 0; i < requests; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if acc.UseRecovery(m, spellings[i%len(spellings)]) {
				winners.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if got := winners.Load(); got != 1 {
		t.Fatalf("%d redemptions accepted, want exactly 1", got)
	}
	if acc.Remaining() != 3 {
		t.Errorf("remaining = %d, want 3", acc.Remaining())
	}
}

// Many requests present one TOTP code at once: exactly one is accepted. And the
// same code presented to twenty accounts at once is accepted by none of them.
func TestE2E_MFA_concurrentCodeUseYieldsOneWinnerAndNoCrossAccountWinner(t *testing.T) {
	m := newModule(t, totp.Config{})
	hostiletest.AtStableStep(t, func(step uint64) string {
		owner := hostiletest.Enroll(t, m, "owner@example.com")
		code := hostiletest.CodeAt(t, owner.Secret, step)
		victims := make([]*hostiletest.Account, 20)
		for i := range victims {
			victims[i] = hostiletest.Enroll(t, m, "victim@example.com")
			for _, off := range []int{-1, 0, 1} {
				if hostiletest.CodeAt(t, victims[i].Secret, uint64(int64(step)+int64(off))) == code {
					return "" // coincidence between random secrets; the run proves nothing
				}
			}
		}
		var (
			wg      sync.WaitGroup
			start   = make(chan struct{})
			winners atomic.Int64
			crossed atomic.Int64
		)
		for i := 0; i < 64; i++ {
			wg.Add(2)
			go func() {
				defer wg.Done()
				<-start
				if m.Verify(ctx, owner.Secret, code, owner) == nil {
					winners.Add(1)
				}
			}()
			go func() {
				defer wg.Done()
				<-start
				v := victims[i%len(victims)]
				if m.Verify(ctx, v.Secret, code, v) == nil {
					crossed.Add(1)
				}
			}()
		}
		close(start)
		wg.Wait()
		if winners.Load() != 1 {
			return "winners = " + strconv.Itoa(int(winners.Load())) + ", want 1"
		}
		if crossed.Load() != 0 {
			return "the code was accepted by a different account"
		}
		return ""
	})
}
