package authcore_test

import (
	"testing"

	"github.com/Glyndor/authcore"
)

// TestLogger_stdLoggerMethodsDoNotPanic exercises every level of the built-in
// stdlib logger. The methods write to os.Stdout; the test asserts only that
// each level runs without panicking, which covers the format-and-Output path.
func TestLogger_stdLoggerMethodsDoNotPanic(t *testing.T) {
	cfg := authcore.DefaultConfig() // EnableLogs = true -> stdLogger
	cfg.KeysDir = t.TempDir()

	ac, err := authcore.New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	log := ac.Logger()
	log.Debug("debug %d", 1)
	log.Info("info %s", "value")
	log.Warn("warn %v", true)
	log.Error("error %s", "boom")
}

// TestLogger_noopLoggerMethodsDoNotPanic exercises every level of the noop
// logger used when logging is disabled. Each call must be a silent no-op.
func TestLogger_noopLoggerMethodsDoNotPanic(t *testing.T) {
	cfg := authcore.DefaultConfig()
	cfg.KeysDir = t.TempDir()
	cfg.EnableLogs = false // -> noopLogger

	ac, err := authcore.New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	log := ac.Logger()
	log.Debug("debug %d", 1)
	log.Info("info %s", "value")
	log.Warn("warn %v", true)
	log.Error("error %s", "boom")
}
