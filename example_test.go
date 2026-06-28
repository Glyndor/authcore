package authcore_test

import (
	"fmt"
	"os"

	"github.com/Glyndor/authcore"
)

func ExampleNew() {
	dir, _ := os.MkdirTemp("", "authcore-example-")
	defer func() { _ = os.RemoveAll(dir) }()

	cfg := authcore.DefaultConfig()
	cfg.EnableLogs = false
	cfg.KeysDir = dir

	auth, err := authcore.New(cfg)
	if err != nil {
		panic(err)
	}
	fmt.Println(auth.Keys() != nil)
	// Output: true
}

func ExampleDefaultConfig() {
	cfg := authcore.DefaultConfig()
	fmt.Println(cfg.KeysDir)
	// Output: .authcore
}
