package username_test

import (
	"errors"
	"fmt"
	"os"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/username"
)

func ExampleNew() {
	dir, _ := os.MkdirTemp("", "authcore-example-")
	defer func() { _ = os.RemoveAll(dir) }()

	auth, _ := authcore.New(authcore.Config{EnableLogs: false, KeysDir: dir})
	mod, err := username.New(auth)
	if err != nil {
		panic(err)
	}
	fmt.Println(mod.Name())
	// Output: username
}

func ExampleUsername_ValidateAndNormalize() {
	dir, _ := os.MkdirTemp("", "authcore-example-")
	defer func() { _ = os.RemoveAll(dir) }()

	auth, _ := authcore.New(authcore.Config{EnableLogs: false, KeysDir: dir})
	mod, _ := username.New(auth)

	got, err := mod.ValidateAndNormalize("  Alice_123  ")
	if err != nil {
		fmt.Println("invalid:", errors.Unwrap(err))
		return
	}
	fmt.Println(got)
	// Output: alice_123
}

func ExampleUsername_ValidateAndNormalize_reserved() {
	dir, _ := os.MkdirTemp("", "authcore-example-")
	defer func() { _ = os.RemoveAll(dir) }()

	auth, _ := authcore.New(authcore.Config{EnableLogs: false, KeysDir: dir})
	mod, _ := username.New(auth)

	_, err := mod.ValidateAndNormalize("admin")
	if errors.Is(err, username.ErrInvalidUsername) {
		fmt.Println("rejected:", errors.Unwrap(err))
	}
	// Output: rejected: "admin" is a reserved name
}
