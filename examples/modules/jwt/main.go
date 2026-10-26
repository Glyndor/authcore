// Command jwt demonstrates the auth/jwt module: creating tokens, verifying
// access tokens, and rotating a refresh token.
package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/jwt"
)

// UserClaims holds application-specific data embedded in the access token.
// Keep it small — it is base64-encoded in every request header.
type UserClaims struct {
	Name string `json:"name"`
	Role string `json:"role"`
}

func main() {
	if err := run(os.Stdout); err != nil {
		log.Fatal(err)
	}
}

// run is the whole example. It writes to w, so the tests read what a user would
// see, and returns an error where the demo used to exit.
func run(w io.Writer) error {
	// -------------------------------------------------------------------------
	// Setup: initialise authcore and the JWT module.
	// -------------------------------------------------------------------------
	dir, cleanup := tempDir()
	defer cleanup()

	auth, err := authcore.New(authcore.Config{KeysDir: dir})
	if err != nil {
		return fmt.Errorf("authcore: %w", err)
	}

	jwtCfg := jwt.DefaultConfig()
	jwtCfg.Issuer = "api-identidad"
	jwtCfg.Audience = []string{"web-app"}

	jwtMod, err := jwt.New[UserClaims](auth, jwtCfg)
	if err != nil {
		return fmt.Errorf("jwt module: %w", err)
	}

	// -------------------------------------------------------------------------
	// Example 1: create a token pair at login.
	// userID must be a UUID v7 string.
	// SessionID (pair.SessionID) is the JTI — store it in your session table.
	// RefreshTokenHash is what you persist in the database, never the raw token.
	// -------------------------------------------------------------------------
	fmt.Fprintln(w, "=== Login: CreateTokens ===")

	userID := "019600ab-1234-7000-8000-000000000001"
	pair, err := jwtMod.CreateTokens(userID, UserClaims{Name: "Ana García", Role: "admin"})
	if err != nil {
		return fmt.Errorf("create tokens: %w", err)
	}

	fmt.Fprintf(w, "access token  : %s…\n", pair.AccessToken[:40])
	fmt.Fprintf(w, "access exp    : %s\n", pair.AccessTokenExpiresAt)
	fmt.Fprintf(w, "refresh exp   : %s\n", pair.RefreshTokenExpiresAt)
	fmt.Fprintf(w, "session ID    : %s\n", pair.SessionID)
	fmt.Fprintf(w, "refresh hash  : %s  ← store this in DB\n", pair.RefreshTokenHash[:16])

	// -------------------------------------------------------------------------
	// Example 2: verify an access token on each authenticated request.
	// -------------------------------------------------------------------------
	fmt.Fprintln(w, "\n=== Authenticated request: VerifyAccessToken ===")

	claims, err := jwtMod.VerifyAccessToken(pair.AccessToken)
	if err != nil {
		return fmt.Errorf("verify access token: %w", err)
	}

	fmt.Fprintf(w, "subject  : %s\n", claims.Subject)
	fmt.Fprintf(w, "name     : %s\n", claims.Extra.Name)
	fmt.Fprintf(w, "role     : %s\n", claims.Extra.Role)
	fmt.Fprintf(w, "token id : %s\n", claims.TokenID)

	// -------------------------------------------------------------------------
	// Example 3: error handling on an expired or tampered token.
	// -------------------------------------------------------------------------
	fmt.Fprintln(w, "\n=== Error handling ===")

	_, err = jwtMod.VerifyAccessToken("not.a.valid.token")
	if errors.Is(err, jwt.ErrTokenMalformed) {
		fmt.Fprintln(w, "ErrTokenMalformed caught correctly")
	}

	// -------------------------------------------------------------------------
	// Example 4: token rotation on refresh.
	// Verify the hash first (constant-time), then issue a new pair and replace
	// the stored hash — both steps must succeed or roll back the transaction.
	// -------------------------------------------------------------------------
	fmt.Fprintln(w, "\n=== Token rotation: RotateTokens ===")

	storedHash := pair.RefreshTokenHash // what you loaded from the database

	if !jwtMod.VerifyRefreshTokenHash(pair.RefreshToken, storedHash) {
		return errors.New("refresh token hash mismatch — possible token theft")
	}

	// Load fresh user data before issuing new claims.
	newPair, err := jwtMod.RotateTokens(pair.RefreshToken, UserClaims{Name: "Ana García", Role: "admin"})
	if err != nil {
		return fmt.Errorf("rotate tokens: %w", err)
	}

	fmt.Fprintf(w, "new access token : %s…\n", newPair.AccessToken[:40])
	fmt.Fprintf(w, "new refresh hash : %s  ← replace old hash in DB\n", newPair.RefreshTokenHash[:16])

	return nil
}

func tempDir() (string, func()) {
	dir, err := os.MkdirTemp("", "authcore-jwt-example-*")
	if err != nil {
		log.Fatalf("create temp dir: %v", err)
	}
	return dir, func() { _ = os.RemoveAll(dir) }
}
