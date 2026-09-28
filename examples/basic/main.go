// Command basic demonstrates how to initialise authcore with different
// configuration strategies.
package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/Glyndor/authcore"
)

func main() {
	// -------------------------------------------------------------------------
	// Example 1: defaults (logs enabled, UTC timezone, keys in ".authcore").
	// In a real application you would omit the KeysDir override and let
	// authcore manage the directory automatically in your project root.
	// -------------------------------------------------------------------------
	dir1, cleanup1 := tempDir()
	defer cleanup1()

	auth, err := authcore.New(authcore.Config{
		EnableLogs: true,
		Timezone:   time.UTC,
		KeysDir:    dir1,
	})
	if err != nil {
		log.Fatalf("failed to initialise authcore: %v", err)
	}

	fmt.Printf("timezone      : %s\n", auth.Config().Timezone)
	fmt.Printf("logs enabled  : %v\n", auth.Config().EnableLogs)
	fmt.Printf("keys dir      : %s\n", auth.Config().KeysDir)
	fmt.Printf("public key    : %x…\n\n", auth.Keys().PublicKey()[:8])

	// -------------------------------------------------------------------------
	// Example 2: custom timezone, logs disabled, explicit keys directory.
	// Useful for tests or environments where the working directory is read-only.
	// -------------------------------------------------------------------------
	bogota, err := time.LoadLocation("America/Bogota")
	if err != nil {
		log.Fatalf("unknown timezone: %v", err)
	}

	dir2, cleanup2 := tempDir()
	defer cleanup2()

	silentAuth, err := authcore.New(authcore.Config{
		EnableLogs: false,
		Timezone:   bogota,
		KeysDir:    dir2,
	})
	if err != nil {
		log.Fatalf("failed to initialise authcore: %v", err)
	}

	fmt.Printf("timezone      : %s\n", silentAuth.Config().Timezone)
	fmt.Printf("logs enabled  : %v\n", silentAuth.Config().EnableLogs)

	// -------------------------------------------------------------------------
	// Example 3: inject a custom logger (e.g. wrap slog, zap, zerolog).
	// -------------------------------------------------------------------------
	dir3, cleanup3 := tempDir()
	defer cleanup3()

	cfg := authcore.DefaultConfig()
	cfg.Logger = &myAppLogger{}
	cfg.KeysDir = dir3

	customAuth, err := authcore.New(cfg)
	if err != nil {
		log.Fatalf("failed to initialise authcore: %v", err)
	}

	// Logger() and Keys() are exposed through the Provider interface so
	// sub-modules can share the same sink and key material.
	_ = customAuth.Logger()
	_ = customAuth.Keys().RefreshSecret()
}

// tempDir creates a temporary directory and returns a cleanup function.
// In production, authcore manages ".authcore" in your project root automatically.
func tempDir() (string, func()) {
	dir, err := os.MkdirTemp("", "authcore-example-*")
	if err != nil {
		log.Fatalf("create temp dir: %v", err)
	}
	return dir, func() { _ = os.RemoveAll(dir) }
}

// myAppLogger is a toy implementation of authcore.Logger.
// In a real application you would wrap slog, zap, or zerolog here.
type myAppLogger struct{}

func (myAppLogger) Debug(msg string, args ...any) { fmt.Printf("[DEBUG] "+msg+"\n", args...) }
func (myAppLogger) Info(msg string, args ...any)  { fmt.Printf("[INFO]  "+msg+"\n", args...) }
func (myAppLogger) Warn(msg string, args ...any)  { fmt.Printf("[WARN]  "+msg+"\n", args...) }
func (myAppLogger) Error(msg string, args ...any) { fmt.Printf("[ERROR] "+msg+"\n", args...) }
