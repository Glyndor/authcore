package verify_test

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

func BenchmarkVerifyAccessToken(b *testing.B) {
	mod := newBenchJWT(b)
	pair, err := mod.CreateTokens(benchSubject, benchClaims{Role: "admin"})
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := mod.VerifyAccessToken(pair.AccessToken); err != nil {
			b.Fatal(err)
		}
	}
}
