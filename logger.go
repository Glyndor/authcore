package authcore

import (
	"fmt"
	"io"
	"log"
	"os"
)

// Logger is the logging interface used throughout authcore.
// Implement this interface to plug in any logging backend (slog, zap, zerolog, etc.).
type Logger interface {
	Debug(msg string, args ...any)
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
}

// ----- noop logger -----

// noopLogger silently discards every log entry.
// It is used when Config.EnableLogs is false.
type noopLogger struct{}

func (noopLogger) Debug(string, ...any) {}
func (noopLogger) Info(string, ...any)  {}
func (noopLogger) Warn(string, ...any)  {}
func (noopLogger) Error(string, ...any) {}

// ----- default stdlib logger -----

// stdLogger is the built-in logger backed by the standard library.
type stdLogger struct {
	debug *log.Logger
	info  *log.Logger
	warn  *log.Logger
	err   *log.Logger
}

// newStdLogger creates a stdLogger that writes to w.
// Pass os.Stdout for normal use; pass any io.Writer for testing.
func newStdLogger(w io.Writer) *stdLogger {
	flags := log.Ldate | log.Ltime | log.LUTC
	return &stdLogger{
		debug: log.New(w, "[DEBUG] authcore: ", flags),
		info:  log.New(w, "[INFO]  authcore: ", flags),
		warn:  log.New(w, "[WARN]  authcore: ", flags),
		err:   log.New(w, "[ERROR] authcore: ", flags),
	}
}

func (l *stdLogger) Debug(msg string, args ...any) { l.debug.Output(2, fmt.Sprintf(msg, args...)) } //nolint:errcheck,gosec
func (l *stdLogger) Info(msg string, args ...any)  { l.info.Output(2, fmt.Sprintf(msg, args...)) }  //nolint:errcheck,gosec
func (l *stdLogger) Warn(msg string, args ...any)  { l.warn.Output(2, fmt.Sprintf(msg, args...)) }  //nolint:errcheck,gosec
func (l *stdLogger) Error(msg string, args ...any) { l.err.Output(2, fmt.Sprintf(msg, args...)) }   //nolint:errcheck,gosec

// newLogger selects the right Logger implementation based on the config.
// If cfg.Logger is set, it is used as-is (bring-your-own-logger).
// If cfg.EnableLogs is true, a default stdlib logger writing to stdout is returned.
// Otherwise a noopLogger is returned.
func newLogger(cfg Config) Logger {
	if cfg.Logger != nil {
		return cfg.Logger
	}
	if cfg.EnableLogs {
		return newStdLogger(os.Stdout)
	}
	return noopLogger{}
}
