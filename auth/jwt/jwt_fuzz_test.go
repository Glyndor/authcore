package jwt

import (
	"testing"

	"github.com/Glyndor/authcore"
)

// FuzzVerifyAccessToken ensures the verifier never panics on arbitrary input.
// All malformed input must error cleanly via the documented sentinels.
func FuzzVerifyAccessToken(f *testing.F) {
	auth, err := authcore.New(authcore.Config{EnableLogs: false, KeysDir: f.TempDir()})
	if err != nil {
		f.Fatal(err)
	}
	mod, err := New[struct{}](auth, DefaultConfig())
	if err != nil {
		f.Fatal(err)
	}

	pair, err := mod.CreateTokens("018f0c8e-9b2a-7c3a-8b1e-1234567890ab", struct{}{})
	if err != nil {
		f.Fatal(err)
	}

	seeds := []string{
		"", ".", "..", "a.b.c",
		"eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.",
		pair.AccessToken, pair.RefreshToken,
		pair.AccessToken + "tampered",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, in string) {
		_, _ = mod.VerifyAccessToken(in)
	})
}

func FuzzIsUUIDv7(f *testing.F) {
	seeds := []string{
		"", "not-a-uuid",
		"018f0c8e-9b2a-7c3a-8b1e-1234567890ab",
		"018f0c8e-9b2a-7c3a-cb1e-1234567890ab",
		"018F0C8E-9B2A-7C3A-8B1E-1234567890AB",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, in string) {
		_ = isUUIDv7(in)
	})
}
