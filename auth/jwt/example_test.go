package jwt_test

import (
	"errors"
	"fmt"
	"os"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/jwt"
)

type AppClaims struct {
	Role string `json:"role"`
}

func ExampleNew() {
	dir, _ := os.MkdirTemp("", "authcore-example-")
	defer func() { _ = os.RemoveAll(dir) }()

	auth, _ := authcore.New(authcore.Config{EnableLogs: false, KeysDir: dir})
	mod, err := jwt.New[AppClaims](auth, jwt.DefaultConfig())
	if err != nil {
		panic(err)
	}
	fmt.Println(mod.Name())
	// Output: jwt
}

func ExampleJWT_CreateTokens() {
	dir, _ := os.MkdirTemp("", "authcore-example-")
	defer func() { _ = os.RemoveAll(dir) }()

	auth, _ := authcore.New(authcore.Config{EnableLogs: false, KeysDir: dir})
	mod, _ := jwt.New[AppClaims](auth, jwt.DefaultConfig())

	pair, err := mod.CreateTokens("018f0c8e-9b2a-7c3a-8b1e-1234567890ab", AppClaims{Role: "admin"})
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println("got pair:", pair.AccessToken != "" && pair.RefreshToken != "" && pair.SessionID != "")
	// Output: got pair: true
}

func ExampleJWT_VerifyAccessToken() {
	dir, _ := os.MkdirTemp("", "authcore-example-")
	defer func() { _ = os.RemoveAll(dir) }()

	auth, _ := authcore.New(authcore.Config{EnableLogs: false, KeysDir: dir})
	mod, _ := jwt.New[AppClaims](auth, jwt.DefaultConfig())

	pair, _ := mod.CreateTokens("018f0c8e-9b2a-7c3a-8b1e-1234567890ab", AppClaims{Role: "admin"})

	claims, err := mod.VerifyAccessToken(pair.AccessToken)
	switch {
	case errors.Is(err, jwt.ErrTokenExpired):
		fmt.Println("expired")
	case errors.Is(err, jwt.ErrTokenInvalid):
		fmt.Println("invalid")
	case err != nil:
		fmt.Println("error:", err)
	default:
		fmt.Println(claims.Extra.Role)
	}
	// Output: admin
}

func ExampleJWT_RotateTokens() {
	dir, _ := os.MkdirTemp("", "authcore-example-")
	defer func() { _ = os.RemoveAll(dir) }()

	auth, _ := authcore.New(authcore.Config{EnableLogs: false, KeysDir: dir})
	mod, _ := jwt.New[AppClaims](auth, jwt.DefaultConfig())

	pair, _ := mod.CreateTokens("018f0c8e-9b2a-7c3a-8b1e-1234567890ab", AppClaims{Role: "user"})

	newPair, err := mod.RotateTokens(pair.RefreshToken, AppClaims{Role: "admin"})
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println(newPair.SessionID == pair.SessionID)
	// Output: true
}
