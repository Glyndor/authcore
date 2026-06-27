package password

import (
	"testing"

	"github.com/Glyndor/authcore"
)

func newBenchModule(b *testing.B) *Password {
	b.Helper()
	auth, err := authcore.New(authcore.Config{EnableLogs: false, KeysDir: b.TempDir()})
	if err != nil {
		b.Fatal(err)
	}
	mod, err := New(auth, Config{Memory: 8 * 1024, Iterations: 1, Parallelism: 1})
	if err != nil {
		b.Fatal(err)
	}
	return mod
}

func BenchmarkHash(b *testing.B) {
	mod := newBenchModule(b)
	pw := "BenchPass123!"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := mod.Hash(pw); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerify(b *testing.B) {
	mod := newBenchModule(b)
	pw := "BenchPass123!"
	hash, err := mod.Hash(pw)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := mod.Verify(pw, hash); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkValidatePolicy(b *testing.B) {
	mod := newBenchModule(b)
	pw := "BenchPass123!"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = mod.ValidatePolicy(pw)
	}
}
