package username

import (
	"testing"

	"github.com/Glyndor/authcore"
)

func BenchmarkValidateAndNormalize(b *testing.B) {
	auth, err := authcore.New(authcore.Config{EnableLogs: false, KeysDir: b.TempDir()})
	if err != nil {
		b.Fatal(err)
	}
	mod, err := New(auth)
	if err != nil {
		b.Fatal(err)
	}
	in := "Alice_123"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := mod.ValidateAndNormalize(in); err != nil {
			b.Fatal(err)
		}
	}
}
