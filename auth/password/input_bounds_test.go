package password

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestPolicyOversizedPlaintextHasBoundedAllocation(t *testing.T) {
	for _, maxLength := range []int{64, 1024} {
		t.Run(fmt.Sprint(maxLength), func(t *testing.T) {
			mod, err := New(fakeProvider{}, Config{
				Memory: 8192, Iterations: 1, Parallelism: 1, MaxLength: maxLength,
			})
			if err != nil {
				t.Fatal(err)
			}
			wantReason := fmt.Sprintf("must be at most %d characters", maxLength)
			for name, call := range map[string]func(string) (string, error){
				"Hash": mod.Hash,
				"ValidatePolicy": func(input string) (string, error) {
					return "", mod.ValidatePolicy(input)
				},
			} {
				t.Run(name, func(t *testing.T) {
					for name, input := range map[string]string{
						"ASCII":            strings.Repeat("a", 131073),
						"decomposed":       strings.Repeat("e\u0301", 43690) + "aaa",
						"large decomposed": strings.Repeat("e\u0301", 1<<20),
					} {
						t.Run(name, func(t *testing.T) {
							var before, after runtime.MemStats
							runtime.ReadMemStats(&before)
							hash, err := call(input)
							runtime.ReadMemStats(&after)
							if hash != "" || !errors.Is(err, ErrWeakPassword) {
								t.Fatalf("hash = %q, error = %v; want empty hash, ErrWeakPassword", hash, err)
							}
							if reason := errors.Unwrap(err); reason == nil || reason.Error() != wantReason {
								t.Errorf("reason = %v; want %q", reason, wantReason)
							}
							if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 64<<10 {
								t.Errorf("allocated %d bytes, want <= 65536", allocated)
							}
						})
					}
				})
			}
		})
	}
}

func TestPolicyAcceptsDecomposedPlaintextAtCharacterLimit(t *testing.T) {
	mod, err := New(fakeProvider{}, Config{
		Memory: 8192, Iterations: 1, Parallelism: 1, MaxLength: 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	input := strings.Repeat("e\u0301", 1020) + "Aa1!"
	if err := mod.ValidatePolicy(input); err != nil {
		t.Fatal(err)
	}
	hash, err := mod.Hash(input)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := mod.Verify(strings.Repeat("é", 1020)+"Aa1!", hash); !ok || err != nil {
		t.Fatalf("Verify NFC = %v, %v; want true, nil", ok, err)
	}
}
