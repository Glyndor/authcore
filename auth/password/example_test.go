package password_test

import (
	"errors"
	"fmt"
	"os"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/password"
)

func ExampleNew() {
	dir, _ := os.MkdirTemp("", "authcore-example-")
	defer func() { _ = os.RemoveAll(dir) }()

	auth, _ := authcore.New(authcore.Config{EnableLogs: false, KeysDir: dir})
	mod, err := password.New(auth)
	if err != nil {
		panic(err)
	}
	fmt.Println(mod.Name())
	// Output: password
}

func ExamplePassword_Hash() {
	dir, _ := os.MkdirTemp("", "authcore-example-")
	defer func() { _ = os.RemoveAll(dir) }()

	auth, _ := authcore.New(authcore.Config{EnableLogs: false, KeysDir: dir})
	mod, _ := password.New(auth, password.Config{Memory: 8 * 1024, Iterations: 1, Parallelism: 1})

	hash, err := mod.Hash("CorrectHorse123!")
	if err != nil {
		fmt.Println("weak:", errors.Unwrap(err))
		return
	}
	fmt.Println(hash[:9]) // PHC prefix only — full hash varies per call
	// Output: $argon2id
}

func ExamplePassword_Verify() {
	dir, _ := os.MkdirTemp("", "authcore-example-")
	defer func() { _ = os.RemoveAll(dir) }()

	auth, _ := authcore.New(authcore.Config{EnableLogs: false, KeysDir: dir})
	mod, _ := password.New(auth, password.Config{Memory: 8 * 1024, Iterations: 1, Parallelism: 1})

	hash, _ := mod.Hash("CorrectHorse123!")
	ok, _ := mod.Verify("CorrectHorse123!", hash)
	fmt.Println(ok)
	// Output: true
}

func ExamplePassword_ValidatePolicy() {
	dir, _ := os.MkdirTemp("", "authcore-example-")
	defer func() { _ = os.RemoveAll(dir) }()

	auth, _ := authcore.New(authcore.Config{EnableLogs: false, KeysDir: dir})
	mod, _ := password.New(auth)

	if err := mod.ValidatePolicy("short"); err != nil {
		fmt.Println("rejected:", errors.Unwrap(err))
	}
	// Output: rejected: must be at least 12 characters
}
