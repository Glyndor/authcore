package rotation_test

import (
	"errors"
	"testing"

	"github.com/Glyndor/authcore/auth/jwt/internal/jwterr"
	"github.com/Glyndor/authcore/auth/jwt/internal/jwttest"
)

// FuzzRotate drives the refresh path with arbitrary text. It must never panic,
// it hands out a new pair only for the one refresh token that was issued (an
// access token, a mutated copy or any other string never rotates), and every
// refusal is one of the documented sentinels.
func FuzzRotate(f *testing.F) {
	rig := jwttest.NewRig[struct{}](jwttest.NewKeys(f), jwttest.DefaultConfig())
	pair, err := rig.CreateTokens("0191b432-b5a7-7c4f-b2e6-7a3f1d2e0007", struct{}{})
	if err != nil {
		f.Fatal(err)
	}
	for _, s := range []string{
		"", ".", "..", "a.b.c", pair.RefreshToken, pair.AccessToken, pair.RefreshToken + "x",
		pair.RefreshToken[:len(pair.RefreshToken)-1], " " + pair.RefreshToken,
		pair.RefreshToken[:20] + "\n" + pair.RefreshToken[20:],
		"eyJhbGciOiJub25lIn0.eyJ0eXBlIjoicmVmcmVzaCJ9.",
	} {
		f.Add(s)
	}
	sentinels := []error{jwterr.ErrTokenExpired, jwterr.ErrTokenInvalid, jwterr.ErrTokenMalformed, jwterr.ErrWrongTokenType, jwterr.ErrTokenRevoked, jwterr.ErrTokenOversized}

	f.Fuzz(func(t *testing.T, in string) {
		next, err := rig.RotateTokens(in, struct{}{})
		if err == nil {
			if in != pair.RefreshToken {
				t.Fatalf("rotated %q, which is not the issued refresh token", in)
			}
			if next == nil || next.RefreshToken == in || next.SessionID != pair.SessionID {
				t.Fatalf("a rotation returned %+v", next)
			}
			return
		}
		if next != nil {
			t.Fatalf("an error came with a pair: %v", err)
		}
		for _, s := range sentinels {
			if errors.Is(err, s) {
				return
			}
		}
		t.Fatalf("RotateTokens(%q) failed with %v, which is none of the documented sentinels", in, err)
	})
}
