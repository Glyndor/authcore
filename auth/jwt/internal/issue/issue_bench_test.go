package issue_test

import (
	"testing"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/jwt"
)

const benchSubject = "018f0c8e-9b2a-7c3a-8b1e-1234567890ab"

type benchClaims struct {
	Role string `json:"role"`
}

func newBenchJWT(b *testing.B) *jwt.JWT[benchClaims] {
	b.Helper()
	auth, err := authcore.New(authcore.Config{EnableLogs: false, KeysDir: b.TempDir()})
	if err != nil {
		b.Fatal(err)
	}
	mod, err := jwt.New[benchClaims](auth, jwt.DefaultConfig())
	if err != nil {
		b.Fatal(err)
	}
	return mod
}

func BenchmarkCreateTokens(b *testing.B) {
	mod := newBenchJWT(b)
	extra := benchClaims{Role: "admin"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := mod.CreateTokens(benchSubject, extra); err != nil {
			b.Fatal(err)
		}
	}
}
