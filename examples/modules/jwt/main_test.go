package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/jwt"
)

const userID = "019600ab-1234-7000-8000-000000000001"

// newModule builds the module the way the example does. issuer and audience
// let a test build a second service over the same keys.
func newModule(t *testing.T, auth authcore.Provider, issuer, audience string) *jwt.JWT[UserClaims] {
	t.Helper()
	cfg := jwt.DefaultConfig()
	cfg.Issuer = issuer
	cfg.Audience = []string{audience}
	mod, err := jwt.New[UserClaims](auth, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return mod
}

func newAuth(t *testing.T) authcore.Provider {
	t.Helper()
	auth, err := authcore.New(authcore.Config{KeysDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	return auth
}

// TestRunPrintsNoCompleteToken runs the example and requires that no complete
// token reaches its output: a token printed by a demo is a token logged by the
// code copied from it.
func TestRunPrintsNoCompleteToken(t *testing.T) {
	var out bytes.Buffer
	if err := run(&out); err != nil {
		t.Fatal(err)
	}
	if regexp.MustCompile(`[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`).MatchString(out.String()) {
		t.Error("the output holds a complete token")
	}
	for _, want := range []string{"ErrTokenMalformed caught correctly", "subject  : " + userID, "role     : admin"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q", want)
		}
	}
}

// TestTokenTypesAreNotInterchangeable checks that each of the two tokens works
// only where its type belongs, and that a malformed input is an error, not a
// panic.
func TestTokenTypesAreNotInterchangeable(t *testing.T) {
	mod := newModule(t, newAuth(t), "api-identidad", "web-app")
	pair, err := mod.CreateTokens(userID, UserClaims{Name: "Ana", Role: "user"})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := mod.VerifyAccessToken(pair.RefreshToken); !errors.Is(err, jwt.ErrWrongTokenType) {
		t.Errorf("a refresh token verified as an access token: %v", err)
	}
	if _, err := mod.RotateTokens(pair.AccessToken, UserClaims{}); err == nil {
		t.Error("an access token was accepted for rotation")
	}

	for name, tok := range map[string]string{
		"empty": "", "dots": "..", "three parts of nothing": "a.b.c", "bearer prefix": "Bearer " + pair.AccessToken,
		"trailing newline": pair.AccessToken + "\n", "huge": strings.Repeat("A", 1<<20), "NUL": "a\x00.b.c",
	} {
		if _, err := mod.VerifyAccessToken(tok); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestTamperedTokensAreRefused edits a valid token the ways an attacker would:
// the role claim, the signature, and the algorithm.
func TestTamperedTokensAreRefused(t *testing.T) {
	mod := newModule(t, newAuth(t), "api-identidad", "web-app")
	pair, err := mod.CreateTokens(userID, UserClaims{Name: "Ana", Role: "user"})
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(pair.AccessToken, ".")
	enc := base64.RawURLEncoding.EncodeToString

	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims map[string]any
	_ = json.Unmarshal(payload, &claims)
	claims["role"] = "admin"
	forged, _ := json.Marshal(claims)

	flipped := []byte(parts[2])
	flipped[0] ^= 1

	for name, tok := range map[string]string{
		"role edited, signature kept": parts[0] + "." + enc(forged) + "." + parts[2],
		"signature bit flipped":       parts[0] + "." + parts[1] + "." + string(flipped),
		"signature dropped":           parts[0] + "." + parts[1] + ".",
		"alg none":                    enc([]byte(`{"alg":"none","typ":"JWT"}`)) + "." + enc(forged) + ".",
		"alg HS256":                   enc([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." + enc(forged) + "." + parts[2],
	} {
		if _, err := mod.VerifyAccessToken(tok); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestTokenOfAnotherServiceIsRefused checks the issuer and audience the example
// configures: a token minted for one service must not open another that
// shares the keys.
func TestTokenOfAnotherServiceIsRefused(t *testing.T) {
	auth := newAuth(t)
	here := newModule(t, auth, "api-identidad", "web-app")
	other := newModule(t, auth, "another-issuer", "another-app")
	otherAudience := newModule(t, auth, "api-identidad", "another-app")

	for name, svc := range map[string]*jwt.JWT[UserClaims]{"another issuer": other, "another audience": otherAudience} {
		pair, err := svc.CreateTokens(userID, UserClaims{Role: "admin"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := here.VerifyAccessToken(pair.AccessToken); err == nil {
			t.Errorf("%s: its access token was accepted", name)
		}
		if _, err := here.RotateTokens(pair.RefreshToken, UserClaims{}); err == nil {
			t.Errorf("%s: its refresh token was accepted", name)
		}
	}
}

// TestRotationRetiresTheOldRefreshToken follows the example's rotation and
// checks the stored-hash comparison fails closed: for the old token, for an
// empty stored hash, and for an empty token.
func TestRotationRetiresTheOldRefreshToken(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mod := newModule(t, newAuth(t), "api-identidad", "web-app")
		pair, _ := mod.CreateTokens(userID, UserClaims{Name: "Ana", Role: "user"})
		time.Sleep(2 * time.Second)

		if !mod.VerifyRefreshTokenHash(pair.RefreshToken, pair.RefreshTokenHash) {
			t.Fatal("the issued token does not match its own hash")
		}
		next, err := mod.RotateTokens(pair.RefreshToken, UserClaims{Name: "Ana", Role: "admin"})
		if err != nil {
			t.Fatal(err)
		}
		if next.RefreshToken == pair.RefreshToken || next.RefreshTokenHash == pair.RefreshTokenHash {
			t.Fatal("rotation returned the same refresh token")
		}
		claims, err := mod.VerifyAccessToken(next.AccessToken)
		if err != nil || claims.Extra.Role != "admin" {
			t.Errorf("the rotated token carries the claims the caller passed in: %v %+v", err, claims)
		}

		if mod.VerifyRefreshTokenHash(pair.RefreshToken, next.RefreshTokenHash) {
			t.Error("the old refresh token matches the new stored hash")
		}
		if mod.VerifyRefreshTokenHash(next.RefreshToken, pair.RefreshTokenHash) {
			t.Error("the new refresh token matches the old stored hash")
		}
		for _, stored := range []string{"", " ", "0"} {
			if mod.VerifyRefreshTokenHash(pair.RefreshToken, stored) {
				t.Errorf("a refresh token matched the stored hash %q", stored)
			}
		}
		if mod.VerifyRefreshTokenHash("", "") || mod.VerifyRefreshTokenHash("", pair.RefreshTokenHash) {
			t.Error("an empty refresh token matched")
		}
	})
}

// TestSubjectMustBeAUUIDv7 checks the documented rule that the subject is an
// opaque id, not the email or a name.
func TestSubjectMustBeAUUIDv7(t *testing.T) {
	mod := newModule(t, newAuth(t), "api-identidad", "web-app")
	for _, sub := range []string{"", "ana@example.com", "admin", "1", "00000000-0000-4000-8000-000000000001", userID + "x"} {
		if _, err := mod.CreateTokens(sub, UserClaims{}); !errors.Is(err, jwt.ErrInvalidSubject) {
			t.Errorf("subject %q: %v, want ErrInvalidSubject", sub, err)
		}
	}
}

// TestTokensExpire moves the clock past each lifetime.
func TestTokensExpire(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mod := newModule(t, newAuth(t), "api-identidad", "web-app")
		pair, _ := mod.CreateTokens(userID, UserClaims{})

		time.Sleep(400 * 24 * time.Hour)
		if _, err := mod.VerifyAccessToken(pair.AccessToken); !errors.Is(err, jwt.ErrTokenExpired) {
			t.Errorf("expired access token: %v", err)
		}
		if _, err := mod.RotateTokens(pair.RefreshToken, UserClaims{}); err == nil {
			t.Error("an expired refresh token rotated")
		}
	})
}
