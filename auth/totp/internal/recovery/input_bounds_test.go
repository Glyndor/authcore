package recovery_test

import (
	"runtime"
	"strings"
	"testing"
)

func TestRecoveryVerificationHasBoundedAllocation(t *testing.T) {
	mod := newTOTP(t)
	for name, code := range map[string]string{
		"separators":    strings.Repeat(" -", 1<<19),
		"letters":       strings.Repeat("A", 1<<20),
		"invalid bytes": strings.Repeat("\xff", 1<<20),
	} {
		t.Run(name, func(t *testing.T) {
			hash, err := mod.HashRecoveryCode(code)
			if err != nil {
				t.Fatal(err)
			}
			stored := []string{hash}
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			idx, ok := mod.VerifyRecoveryCode(code, stored)
			runtime.ReadMemStats(&after)
			if ok || idx != 0 {
				t.Errorf("VerifyRecoveryCode = %d, %v; want 0, false", idx, ok)
			}
			if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 64<<10 {
				t.Errorf("VerifyRecoveryCode allocated %d bytes, want <= 65536", allocated)
			}
		})
	}
}

func TestRecoveryVerificationPreservesGrouping(t *testing.T) {
	mod := newTOTP(t)
	const code = "abcdefgh-ijklmnop"
	hash, err := mod.HashRecoveryCode(code)
	if err != nil {
		t.Fatal(err)
	}
	stored := []string{"unrelated", hash}
	for _, input := range []string{code, "ABCDEFGHIJKLMNOP", " a-b-c-d-e-f-g-h i-j-k-l-m-n-o-p ", strings.Repeat(" -", 1<<19) + code} {
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		idx, ok := mod.VerifyRecoveryCode(input, stored)
		runtime.ReadMemStats(&after)
		if !ok || idx != 1 {
			t.Fatalf("VerifyRecoveryCode = %d, %v; want 1, true", idx, ok)
		}
		if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 64<<10 {
			t.Errorf("VerifyRecoveryCode allocated %d bytes, want <= 65536", allocated)
		}
	}
}
