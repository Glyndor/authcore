package hostiletest

import (
	"fmt"
	"strings"
	"sync"

	"github.com/Glyndor/authcore"
)

// SilentProvider supplies the authcore.Provider that oauth.New asks for.
type SilentProvider struct{ Log authcore.Logger }

// Config returns the default authcore configuration.
func (SilentProvider) Config() authcore.Config { return authcore.DefaultConfig() }

// Logger returns the configured logger, or one that drops everything.
func (p SilentProvider) Logger() authcore.Logger {
	if p.Log != nil {
		return p.Log
	}
	return discardLogger{}
}

// Keys returns no key store: the OAuth client does not need one.
func (SilentProvider) Keys() authcore.Keys { return nil }

// DiscardLogger drops everything.
type discardLogger struct{}

func (discardLogger) Debug(string, ...any) {}

func (discardLogger) Info(string, ...any) {}

func (discardLogger) Warn(string, ...any) {}

func (discardLogger) Error(string, ...any) {}

// CaptureLogger records every line the library logs.
type CaptureLogger struct {
	mu    sync.Mutex
	lines []string
}

func (l *CaptureLogger) record(msg string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(msg, args...))
}

// Debug records the line.
func (l *CaptureLogger) Debug(m string, a ...any) { l.record(m, a...) }

// Info records the line.
func (l *CaptureLogger) Info(m string, a ...any) { l.record(m, a...) }

// Warn records the line.
func (l *CaptureLogger) Warn(m string, a ...any) { l.record(m, a...) }

func (l *CaptureLogger) Error(m string, a ...any) { l.record(m, a...) }

func (l *CaptureLogger) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}
