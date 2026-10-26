package totp_test

import (
	"strings"
	"sync"
	"testing"

	"github.com/Glyndor/authcore/auth/totp"
)

// A recovery code is found by value in the stored list wherever it sits, in
// any of the spellings a user types, and nothing else is found: not a near
// miss, not another script's lookalike, not an empty string.
func TestHostile_Recovery_lookupIsExactOverTheNormalisedForm(t *testing.T) {
	m := newModule(t, totp.Config{RecoveryCodeCount: 10})
	enr, err := m.Enroll("user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	for i, code := range enr.RecoveryCodes {
		idx, ok := m.VerifyRecoveryCode(code, enr.RecoveryHashes)
		if !ok || idx != i {
			t.Fatalf("code %d found at %d, %v", i, idx, ok)
		}
	}

	target := enr.RecoveryCodes[3]
	plain := strings.ReplaceAll(target, "-", "")
	for name, spelled := range map[string]string{
		"lower case":      strings.ToLower(target),
		"no hyphen":       plain,
		"spaces":          plain[:4] + " " + plain[4:8] + " " + plain[8:12] + " " + plain[12:],
		"padded":          "  " + target + "  ",
		"hyphen as space": strings.Replace(target, "-", " ", 1),
	} {
		if idx, ok := m.VerifyRecoveryCode(spelled, enr.RecoveryHashes); !ok || idx != 3 {
			t.Errorf("%s: %q found at %d, %v; want index 3", name, spelled, idx, ok)
		}
	}

	flip := func(s string, i int) string {
		b := []byte(s)
		if b[i] == 'A' {
			b[i] = 'B'
		} else {
			b[i] = 'A'
		}
		return string(b)
	}
	for name, miss := range map[string]string{
		"empty":               "",
		"only hyphens":        "----",
		"first character off": flip(target, 0),
		"last character off":  flip(target, len(target)-1),
		"truncated":           target[:len(target)-1],
		"extended":            target + "A",
		"doubled":             target + target,
		"tab separated":       strings.Replace(target, "-", "\t", 1),
		"newline inside":      target[:4] + "\n" + target[4:],
		"NUL inside":          target[:4] + "\x00" + target[4:],
		"zero width space":    target[:4] + "\u200b" + target[4:],
		"fullwidth hyphen":    strings.Replace(target, "-", "\uff0d", 1),
		"cyrillic lookalike":  "\u0410" + target[1:],
		"digit zero for O":    strings.Replace(target, "O", "0", 1) + "x",
		"one MiB":             strings.Repeat("A", 1<<20),
		"another account's":   mustEnrollCode(t, m),
	} {
		if idx, ok := m.VerifyRecoveryCode(miss, enr.RecoveryHashes); ok {
			t.Errorf("%s: %q was found at %d", name, miss, idx)
		}
	}

	if idx, ok := m.VerifyRecoveryCode(target, nil); ok {
		t.Errorf("found in a nil list at %d", idx)
	}
	if idx, ok := m.VerifyRecoveryCode(target, []string{"", "x", strings.ToUpper(enr.RecoveryHashes[3])}); ok {
		t.Errorf("matched a malformed or re-cased stored hash at %d", idx)
	}
}

func mustEnrollCode(t testing.TB, m *totp.TOTP) string {
	t.Helper()
	enr, err := m.Enroll("other@example.com")
	if err != nil {
		t.Fatal(err)
	}
	return enr.RecoveryCodes[0]
}

// Recovery codes are single-use because the application removes the entry it
// is told about. The module's part is to be stateless and exact: the same list
// and code always give the same index, even from many goroutines, and after the
// entry is removed the code is gone.
func TestHostile_Recovery_codeIsGoneOnceTheEntryIsRemoved(t *testing.T) {
	m := newModule(t)
	enr, _ := m.Enroll("user@example.com")
	code := enr.RecoveryCodes[5]

	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if idx, ok := m.VerifyRecoveryCode(code, enr.RecoveryHashes); !ok || idx != 5 {
				t.Errorf("concurrent lookup = %d, %v; want 5, true", idx, ok)
			}
		}()
	}
	wg.Wait()

	remaining := append(append([]string{}, enr.RecoveryHashes[:5]...), enr.RecoveryHashes[6:]...)
	if idx, ok := m.VerifyRecoveryCode(code, remaining); ok {
		t.Fatalf("a consumed code was found again at %d", idx)
	}
	if idx, ok := m.VerifyRecoveryCode(enr.RecoveryCodes[6], remaining); !ok || idx != 5 {
		t.Fatalf("the code after the removed one = %d, %v; want index 5", idx, ok)
	}
}

// The recovery hash is keyed with the deployment's secret, so a list of hashes
// taken from one deployment is not a list of codes anywhere else.
func TestHostile_Recovery_hashesAreBoundToTheDeployment(t *testing.T) {
	a, b := newModule(t), newModule(t)
	enr, _ := a.Enroll("user@example.com")
	if _, ok := b.VerifyRecoveryCode(enr.RecoveryCodes[0], enr.RecoveryHashes); ok {
		t.Fatal("a recovery hash from another deployment verified")
	}
	hb, _ := b.HashRecoveryCode(enr.RecoveryCodes[0])
	if hb == enr.RecoveryHashes[0] {
		t.Fatal("two deployments hashed one code to the same value")
	}
}
