package verify_test

import (
	"errors"
	"testing"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/jwt"
)

// FuzzVerifyAccessToken drives the verifier with arbitrary input. It must
// never panic, the only input it accepts is the access token the module
// issued, and every refusal is one of the documented sentinels. Until
// 2026-09-25 the target discarded the result, so it checked none of that.
func FuzzVerifyAccessToken(f *testing.F) {
	auth, err := authcore.New(authcore.Config{EnableLogs: false, KeysDir: f.TempDir()})
	if err != nil {
		f.Fatal(err)
	}
	mod, err := jwt.New[struct{}](auth, jwt.DefaultConfig())
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
		pair.AccessToken[:20] + "\n" + pair.AccessToken[20:],
	}
	for _, s := range seeds {
		f.Add(s)
	}

	sentinels := []error{jwt.ErrTokenExpired, jwt.ErrTokenInvalid, jwt.ErrTokenMalformed, jwt.ErrWrongTokenType, jwt.ErrTokenRevoked, jwt.ErrTokenOversized}

	f.Fuzz(func(t *testing.T, in string) {
		claims, err := mod.VerifyAccessToken(in)
		if err == nil {
			if in != pair.AccessToken {
				t.Fatalf("accepted %q, which is not the issued access token", in)
			}
			if claims.Subject != "018f0c8e-9b2a-7c3a-8b1e-1234567890ab" {
				t.Fatalf("the issued token verified with subject %q", claims.Subject)
			}
			return
		}
		for _, s := range sentinels {
			if errors.Is(err, s) {
				return
			}
		}
		t.Fatalf("VerifyAccessToken(%q) failed with %v, which is none of the documented sentinels", in, err)
	})
}
