// Command basic demonstrates how to initialise authcore with different
// configuration strategies.
package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/Glyndor/authcore"
)

func main() {
	if err := run(os.Stdout); err != nil {
		log.Fatal(err)
	}
}

// run is the whole example. It writes to w, so the tests read what a user would
// see, and returns an error where the demo used to exit.
func run(w io.Writer) error {
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
		return fmt.Errorf("failed to initialise authcore: %w", err)
	}

	fmt.Fprintf(w, "timezone      : %s\n", auth.Config().Timezone)
	fmt.Fprintf(w, "logs enabled  : %v\n", auth.Config().EnableLogs)
	fmt.Fprintf(w, "keys dir      : %s\n", auth.Config().KeysDir)
	fmt.Fprintf(w, "public key    : %x…\n\n", auth.Keys().PublicKey()[:8])

	// -------------------------------------------------------------------------
	// Example 2: custom timezone, logs disabled, explicit keys directory.
	// Useful for tests or environments where the working directory is read-only.
	// -------------------------------------------------------------------------
	bogota, err := time.LoadLocation("America/Bogota")
	if err != nil {
		return fmt.Errorf("unknown timezone: %w", err)
	}

	dir2, cleanup2 := tempDir()
	defer cleanup2()

	silentAuth, err := authcore.New(authcore.Config{
		EnableLogs: false,
		Timezone:   bogota,
		KeysDir:    dir2,
	})
	if err != nil {
		return fmt.Errorf("failed to initialise authcore: %w", err)
	}

	fmt.Fprintf(w, "timezone      : %s\n", silentAuth.Config().Timezone)
	fmt.Fprintf(w, "logs enabled  : %v\n", silentAuth.Config().EnableLogs)

	// -------------------------------------------------------------------------
	// Example 3: inject a custom logger (e.g. wrap slog, zap, zerolog).
	// -------------------------------------------------------------------------
	dir3, cleanup3 := tempDir()
	defer cleanup3()

	cfg := authcore.DefaultConfig()
	cfg.Logger = &myAppLogger{w: w}
	cfg.KeysDir = dir3

	customAuth, err := authcore.New(cfg)
	if err != nil {
		return fmt.Errorf("failed to initialise authcore: %w", err)
	}

	// Logger() and Keys() are exposed through the Provider interface so
	// sub-modules can share the same sink and key material.
	_ = customAuth.Logger()
	_ = customAuth.Keys().RefreshSecret()

	return nil
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
type myAppLogger struct{ w io.Writer }

func (l myAppLogger) Debug(msg string, args ...any) { fmt.Fprintf(l.w, "[DEBUG] "+msg+"\n", args...) }
func (l myAppLogger) Info(msg string, args ...any)  { fmt.Fprintf(l.w, "[INFO]  "+msg+"\n", args...) }
func (l myAppLogger) Warn(msg string, args ...any)  { fmt.Fprintf(l.w, "[WARN]  "+msg+"\n", args...) }
func (l myAppLogger) Error(msg string, args ...any) { fmt.Fprintf(l.w, "[ERROR] "+msg+"\n", args...) }
