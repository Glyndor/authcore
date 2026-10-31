package authcore

import (
	"os"

	"github.com/Glyndor/authcore/internal/logging"
)

// Logger is the logging interface used throughout authcore.
// Implement this interface to plug in any logging backend (slog, zap, zerolog, etc.).
// The arguments are printf operands, not key/value pairs: wrap a structured logger so
// the message is formatted with fmt.Sprintf first (docs/guides/configuration.md).
type Logger interface {
	Debug(msg string, args ...any)
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
}

// newLogger selects the right Logger implementation based on the config.
// If cfg.Logger is set, it is used as-is (bring-your-own-logger).
// If cfg.EnableLogs is true, a default stdlib logger writing to stdout is returned.
// Otherwise a noopLogger is returned.
func newLogger(cfg Config) Logger {
	if cfg.Logger != nil {
		return cfg.Logger
	}
	if cfg.EnableLogs {
		return logging.NewStd(os.Stdout)
	}
	return logging.Noop{}
}
