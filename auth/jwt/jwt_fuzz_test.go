package jwt

import (
	"errors"
	"regexp"
	"testing"

	"github.com/Glyndor/authcore"
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
		pair.AccessToken[:20] + "\n" + pair.AccessToken[20:],
	}
	for _, s := range seeds {
		f.Add(s)
	}

	sentinels := []error{ErrTokenExpired, ErrTokenInvalid, ErrTokenMalformed, ErrWrongTokenType, ErrTokenRevoked, ErrTokenOversized}

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

// uuidV7Shape is RFC 9562 section 5.7 written apart from isUUIDv7: eight,
// four, "7" plus three, one of [89ab] plus three, and twelve hex digits.
var uuidV7Shape = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-7[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)

func FuzzIsUUIDv7(f *testing.F) {
	seeds := []string{
		"", "not-a-uuid",
		"018f0c8e-9b2a-7c3a-8b1e-1234567890ab",
		"018f0c8e-9b2a-7c3a-cb1e-1234567890ab", // variant c
		"018F0C8E-9B2A-7C3A-8B1E-1234567890AB",
		"018f0c8e-9b2a-4c3a-8b1e-1234567890ab", // version 4
		"018f0c8e9-b2a-7c3a-8b1e-1234567890ab", // a dash moved
		"018f0c8e09b2a07c3a08b1e01234567890ab", // hex digits where the dashes go: only the dash check refuses it
		"018f0c8e-9b2a-7c3a-8b1e-1234567890ag", // a non-hex byte
		"018f0c8e-9b2a-7c3a-8b1e-1234567890a",  // one short
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, in string) {
		if got, want := isUUIDv7(in), uuidV7Shape.MatchString(in); got != want {
			t.Fatalf("isUUIDv7(%q) = %v, the shape says %v", in, got, want)
		}
	})
}
