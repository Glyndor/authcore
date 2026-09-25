package authcore_test

import (
	"io"
	"os"
	"testing"

	"github.com/Glyndor/authcore"
)

// TestLogger_stdLoggerMethodsDoNotPanic exercises every level of the built-in
// stdlib logger. The methods write to os.Stdout; the test captures the
// output and asserts at least one byte was produced, so the methods are
// proved to actually run (not just "did not panic").
func TestLogger_stdLoggerMethodsDoNotPanic(t *testing.T) {
	cfg := authcore.DefaultConfig() // EnableLogs = true -> stdLogger
	cfg.KeysDir = t.TempDir()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	origStdout := os.Stdout
	os.Stdout = w
	t.Cleanup(func() {
		os.Stdout = origStdout
		_ = r.Close()
	})

	ac, err := authcore.New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	log := ac.Logger()
	log.Debug("debug %d", 1)
	log.Info("info %s", "value")
	log.Warn("warn %v", true)
	log.Error("error %s", "boom")
	_ = w.Close()

	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read captured stdout: %v", err)
	}
	if len(got) == 0 {
		t.Error("EnableLogs=true with no custom Logger must write to stdout; captured output is empty")
	}
}

// TestLogger_noopLoggerMethodsDoNotPanic exercises every level of the noop
// logger used when logging is disabled. Each call must be a silent no-op:
// the test captures stdout and asserts zero bytes were written. A
// sabotage that returns a stdLogger (writing to os.Stdout) instead of
// a noopLogger would write bytes during ac.log.Info("authcore
// initialised ...") inside New, and this assertion fails.
func TestLogger_noopLoggerMethodsDoNotPanic(t *testing.T) {
	cfg := authcore.DefaultConfig()
	cfg.KeysDir = t.TempDir()
	cfg.EnableLogs = false // -> noopLogger

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	origStdout := os.Stdout
	os.Stdout = w
	t.Cleanup(func() {
		os.Stdout = origStdout
		_ = r.Close()
	})

	ac, err := authcore.New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	log := ac.Logger()
	log.Debug("debug %d", 1)
	log.Info("info %s", "value")
	log.Warn("warn %v", true)
	log.Error("error %s", "boom")
	_ = w.Close()

	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read captured stdout: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("EnableLogs=false must produce no stdout output; captured %q", got)
	}
}
