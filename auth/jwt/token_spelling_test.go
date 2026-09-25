package jwt

import (
	"errors"
	"strings"
	"testing"
)

// flipLastUnusedBit changes the last base64url character of s so it decodes
// to the same bytes under a lenient decoder.
func flipLastUnusedBit(s string) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	i := strings.IndexByte(alphabet, s[len(s)-1])
	return s[:len(s)-1] + string(alphabet[i^1])
}

func TestIssuedTokensHaveOneSpelling(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	pair, err := j.CreateTokens(testSubject, struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.VerifyAccessToken(pair.AccessToken); err != nil {
		t.Fatalf("the access token as issued: %v", err)
	}
	for name, tok := range map[string]string{
		"access, line break":      pair.AccessToken[:20] + "\r\n" + pair.AccessToken[20:],
		"access, unused bits set": flipLastUnusedBit(pair.AccessToken),
	} {
		if _, err := j.VerifyAccessToken(tok); !errors.Is(err, ErrTokenMalformed) {
			t.Errorf("%s: %v, want ErrTokenMalformed", name, err)
		}
	}
	for name, tok := range map[string]string{
		"refresh, line break":      pair.RefreshToken[:20] + "\n" + pair.RefreshToken[20:],
		"refresh, unused bits set": flipLastUnusedBit(pair.RefreshToken),
	} {
		if _, err := j.RotateTokens(tok, struct{}{}); !errors.Is(err, ErrTokenMalformed) {
			t.Errorf("%s: %v, want ErrTokenMalformed", name, err)
		}
	}
	if _, err := j.RotateTokens(pair.RefreshToken, struct{}{}); err != nil {
		t.Fatalf("the refresh token as issued: %v", err)
	}
}
