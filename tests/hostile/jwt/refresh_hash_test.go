package jwt_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/jwt"
)

// referenceHash is HMAC-SHA256 in lower-case hex, computed directly.
func referenceHash(secret []byte, token string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(token))
	return hex.EncodeToString(mac.Sum(nil))
}

// HashRefreshToken is HMAC-SHA256 of the exact token bytes under the refresh
// secret, whatever the token holds, at one fixed length.
func TestHostile_RefreshHash_matchesAnIndependentHMACForEveryInput(t *testing.T) {
	e := newEnv(t)
	m := e.module(t, jwt.Config{})
	for name, token := range map[string]string{
		"empty":            "",
		"one byte":         "a",
		"NUL":              "\x00",
		"NUL padded":       "abc\x00\x00",
		"unicode":          "tóken-日本-\U0001f600",
		"combining":        "é",
		"invalid UTF-8":    "\xff\xfe\xfd",
		"block size":       strings.Repeat("b", 64),
		"block size + 1":   strings.Repeat("b", 65),
		"two blocks":       strings.Repeat("b", 128),
		"8 KiB":            strings.Repeat("c", 8<<10),
		"1 MiB":            strings.Repeat("d", 1<<20),
		"dots and padding": "a.b.c==",
		"hex lookalike":    strings.Repeat("a", 64),
	} {
		got, err := m.HashRefreshToken(token)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if want := referenceHash(e.secret, token); got != want {
			t.Errorf("%s: HashRefreshToken = %s, want %s", name, got, want)
		}
		if len(got) != 64 || got != strings.ToLower(got) {
			t.Errorf("%s: hash %q is not 64 lower-case hex characters", name, got)
		}
	}
}

// Tokens that differ in any way hash differently: a prefix, an extension, a
// trailing NUL, a case change, an equal-length swap. A collision here would let
// one stored hash stand for two refresh tokens.
func TestHostile_RefreshHash_nearbyTokensNeverCollide(t *testing.T) {
	e := newEnv(t)
	m := e.module(t, jwt.Config{})
	base := "eyJhbGciOiJFZERTQSJ9.eyJ0eXBlIjoicmVmcmVzaCJ9.c2ln"
	variants := []string{base, base + "\x00", base + " ", base + ".", strings.ToUpper(base), base[:len(base)-1], base[1:],
		"x" + base, strings.Replace(base, "a", "b", 1), strings.Repeat(base, 2), "", "\x00"}
	seen := map[string]string{}
	for _, v := range variants {
		h, _ := m.HashRefreshToken(v)
		if prev, dup := seen[h]; dup {
			t.Fatalf("%q and %q hash to the same value", prev, v)
		}
		seen[h] = v
	}
}

// VerifyRefreshTokenHash is an exact comparison of the 64-character digest.
// Spelling variants of the right digest are different strings and are refused:
// upper case, a "0x" prefix, surrounding space, a truncated digest, a digest
// with a suffix, the empty string.
func TestHostile_RefreshHash_verifyIsExactOverTheDigestSpelling(t *testing.T) {
	e := newEnv(t)
	m := e.module(t, jwt.Config{})
	token := "some-refresh-token"
	good, _ := m.HashRefreshToken(token)
	if !m.VerifyRefreshTokenHash(token, good) {
		t.Fatal("control: the right digest was refused")
	}
	for name, stored := range map[string]string{
		"upper case":       strings.ToUpper(good),
		"0x prefix":        "0x" + good,
		"leading space":    " " + good,
		"trailing space":   good + " ",
		"trailing NUL":     good + "\x00",
		"trailing newline": good + "\n",
		"truncated":        good[:63],
		"first half":       good[:32],
		"doubled":          good + good,
		"empty":            "",
		"other token":      referenceHash(e.secret, token+"x"),
		"unkeyed SHA-256":  hex.EncodeToString(sha256Sum(token)),
		"all zero":         strings.Repeat("0", 64),
	} {
		if m.VerifyRefreshTokenHash(token, stored) {
			t.Errorf("%s: a variant of the digest was accepted", name)
		}
	}
	if m.VerifyRefreshTokenHash(token+"x", good) || m.VerifyRefreshTokenHash("", good) {
		t.Error("a different token verified against the stored digest")
	}
}

func sha256Sum(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}
