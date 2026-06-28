package email_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/email"
)

func ExampleNew() {
	dir, _ := os.MkdirTemp("", "authcore-example-")
	defer func() { _ = os.RemoveAll(dir) }()

	auth, _ := authcore.New(authcore.Config{EnableLogs: false, KeysDir: dir})
	mod, err := email.New(auth)
	if err != nil {
		panic(err)
	}
	defer mod.Close()
	fmt.Println(mod.Name())
	// Output: email
}

func ExampleEmail_ValidateAndNormalize() {
	dir, _ := os.MkdirTemp("", "authcore-example-")
	defer func() { _ = os.RemoveAll(dir) }()

	auth, _ := authcore.New(authcore.Config{EnableLogs: false, KeysDir: dir})
	mod, _ := email.New(auth)
	defer mod.Close()

	got, err := mod.ValidateAndNormalize("  User@Example.COM  ")
	if err != nil {
		fmt.Println("invalid:", err)
		return
	}
	fmt.Println(got)
	// Output: user@example.com
}

func ExampleEmail_VerifyDomain() {
	dir, _ := os.MkdirTemp("", "authcore-example-")
	defer func() { _ = os.RemoveAll(dir) }()

	auth, _ := authcore.New(authcore.Config{EnableLogs: false, KeysDir: dir})
	mod, _ := email.New(auth)
	defer mod.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err := mod.VerifyDomain(ctx, "user@example.com")
	switch {
	case errors.Is(err, email.ErrDomainNoMX):
		fmt.Println("no MX records — block registration")
	case errors.Is(err, email.ErrDomainUnresolvable):
		fmt.Println("DNS soft failure — log and proceed")
	case err != nil:
		fmt.Println("error:", err)
	default:
		fmt.Println("MX OK")
	}
}
