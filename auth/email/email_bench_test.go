package email

import (
	"testing"

	"github.com/Glyndor/authcore"
)

func newBenchEmail(b *testing.B) *Email {
	b.Helper()
	auth, err := authcore.New(authcore.Config{EnableLogs: false, KeysDir: b.TempDir()})
	if err != nil {
		b.Fatal(err)
	}
	mod, err := New(auth)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(mod.Close)
	return mod
}

func BenchmarkValidateAndNormalize(b *testing.B) {
	mod := newBenchEmail(b)
	addr := "User@Example.COM"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := mod.ValidateAndNormalize(addr); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkValidateAndNormalizeInvalid(b *testing.B) {
	mod := newBenchEmail(b)
	addr := "not-an-email"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = mod.ValidateAndNormalize(addr)
	}
}
