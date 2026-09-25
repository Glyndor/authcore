package username

import (
	"errors"
	"strings"
	"testing"

	"github.com/Glyndor/authcore"
)

type nilLoggerProvider struct{ fakeProvider }

func (nilLoggerProvider) Logger() authcore.Logger { return nil }

// A nil provider or logger panicked until 2026-09-25.
func TestNewWithConfig_refusesANilProviderOrLogger(t *testing.T) {
	if _, err := New(nil); !errors.Is(err, ErrInvalidConfig) || !strings.Contains(err.Error(), "provider is nil") {
		t.Errorf("New(nil) = %v, want ErrInvalidConfig", err)
	}
	if _, err := NewWithConfig(nilLoggerProvider{}, Config{}); !errors.Is(err, ErrInvalidConfig) || !strings.Contains(err.Error(), "Logger() returned nil") {
		t.Errorf("nil logger = %v, want ErrInvalidConfig", err)
	}
	if _, err := New(fakeProvider{}); err != nil {
		t.Fatalf("a real provider: %v", err)
	}
}
