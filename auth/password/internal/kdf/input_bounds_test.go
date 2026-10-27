package kdf_test

import (
	"errors"
	"runtime"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/password"
	"github.com/Glyndor/authcore/auth/password/internal/kdf"
	"golang.org/x/text/unicode/norm"
)

func boundedInputModule(t *testing.T, maxLength int) *password.Password {
	t.Helper()
	mod, err := password.New(fakeProvider{}, password.Config{
		Memory: 8192, Iterations: 1, Parallelism: 1, MaxLength: maxLength,
	})
	if err != nil {
		t.Fatal(err)
	}
	return mod
}

func TestVerifyOversizedPlaintextHasBoundedAllocation(t *testing.T) {
	mod := boundedInputModule(t, 64)
	hash, err := mod.Hash("Correct-Horse-9!")
	if err != nil {
		t.Fatal(err)
	}
	for name, input := range map[string]string{
		"ASCII":            strings.Repeat("a", (128<<10)+1),
		"decomposed":       strings.Repeat("e\u0301", (128<<10)/3+1),
		"large decomposed": strings.Repeat("e\u0301", 1<<20),
	} {
		t.Run(name, func(t *testing.T) {
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			ok, err := mod.Verify(input, hash)
			runtime.ReadMemStats(&after)
			if ok || err != nil {
				t.Fatalf("Verify = %v, %v; want false, nil", ok, err)
			}
			if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 64<<10 {
				t.Errorf("Verify allocated %d bytes, want <= 65536", allocated)
			}
		})
	}
	if ok, err := mod.Verify(strings.Repeat("a", (128<<10)+1), "invalid"); ok || err != nil {
		t.Fatalf("oversized credential = %v, %v; want false, nil", ok, err)
	}
	if ok, err := mod.Verify("reasonable", "invalid"); ok || !errors.Is(err, password.ErrInvalidHash) {
		t.Fatalf("invalid hash = %v, %v; want false, ErrInvalidHash", ok, err)
	}
}

func TestVerifyPlaintextCeilingIsIndependentOfPolicy(t *testing.T) {
	mod := boundedInputModule(t, 64)
	for name, input := range map[string]string{
		"at byte ceiling":    strings.Repeat("a", 128<<10),
		"historical Unicode": strings.Repeat("\U0001f600", 1020) + "Aa1!",
		"decomposed Unicode": norm.NFD.String(strings.Repeat("\u1f82", 1020) + "Aa1!"),
	} {
		t.Run(name, func(t *testing.T) {
			hash, err := kdf.Hash(norm.NFC.String(input), cheap)
			if err != nil {
				t.Fatal(err)
			}
			if ok, err := mod.Verify(input, hash); !ok || err != nil {
				t.Fatalf("Verify = %v, %v; want true, nil", ok, err)
			}
		})
	}
	input := strings.Repeat("a", (128<<10)+1)
	hash, err := kdf.Hash(input, cheap)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := mod.Verify(input, hash); ok || err != nil {
		t.Fatalf("above byte ceiling = %v, %v; want false, nil", ok, err)
	}
}
