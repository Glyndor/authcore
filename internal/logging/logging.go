// Package logging holds the built-in loggers of the root package: one that
// discards every entry and one backed by the standard library.
package logging

import (
	"fmt"
	"io"
	"log"
)

// Noop silently discards every log entry.
// It is used when Config.EnableLogs is false.
type Noop struct{}

// Debug discards the entry.
func (Noop) Debug(string, ...any) {}

// Info discards the entry.
func (Noop) Info(string, ...any) {}

// Warn discards the entry.
func (Noop) Warn(string, ...any) {}

// Error discards the entry.
func (Noop) Error(string, ...any) {}

// Std is the built-in logger backed by the standard library.
type Std struct {
	debug *log.Logger
	info  *log.Logger
	warn  *log.Logger
	err   *log.Logger
}

// NewStd creates a Std that writes to w.
// Pass os.Stdout for normal use; pass any io.Writer for testing.
func NewStd(w io.Writer) *Std {
	flags := log.Ldate | log.Ltime | log.LUTC
	return &Std{
		debug: log.New(w, "[DEBUG] authcore: ", flags),
		info:  log.New(w, "[INFO]  authcore: ", flags),
		warn:  log.New(w, "[WARN]  authcore: ", flags),
		err:   log.New(w, "[ERROR] authcore: ", flags),
	}
}

// Debug writes the entry at DEBUG level.
func (l *Std) Debug(msg string, args ...any) { l.debug.Output(2, fmt.Sprintf(msg, args...)) } //nolint:errcheck,gosec
// Info writes the entry at INFO level.
func (l *Std) Info(msg string, args ...any) { l.info.Output(2, fmt.Sprintf(msg, args...)) } //nolint:errcheck,gosec
// Warn writes the entry at WARN level.
func (l *Std) Warn(msg string, args ...any) { l.warn.Output(2, fmt.Sprintf(msg, args...)) } //nolint:errcheck,gosec
// Error writes the entry at ERROR level.
func (l *Std) Error(msg string, args ...any) { l.err.Output(2, fmt.Sprintf(msg, args...)) } //nolint:errcheck,gosec
