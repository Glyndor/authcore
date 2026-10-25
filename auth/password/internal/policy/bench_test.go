package policy_test

import (
	"testing"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/password"
)

func newBenchModule(b *testing.B) *password.Password {
	b.Helper()
	auth, err := authcore.New(authcore.Config{EnableLogs: false, KeysDir: b.TempDir()})
	if err != nil {
		b.Fatal(err)
	}
	mod, err := password.New(auth, password.Config{Memory: 8 * 1024, Iterations: 1, Parallelism: 1})
	if err != nil {
		b.Fatal(err)
	}
	return mod
}

func BenchmarkValidatePolicy(b *testing.B) {
	mod := newBenchModule(b)
	pw := "BenchPass123!"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = mod.ValidatePolicy(pw)
	}
}
