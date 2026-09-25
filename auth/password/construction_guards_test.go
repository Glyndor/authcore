package password

import (
	"errors"
	"strings"
	"testing"

	"github.com/Glyndor/authcore"
)

// New refuses a nil provider or logger and a second Config (2026-09-25):
// the first two panicked and the third was dropped without a word.

type nilLoggerProvider struct{ fakeProvider }

func (nilLoggerProvider) Logger() authcore.Logger { return nil }

func TestNew_refusesWhatItCannotUse(t *testing.T) {
	for name, tc := range map[string]struct {
		build func() (*Password, error)
		want  string
	}{
		"nil provider": {func() (*Password, error) { return New(nil) }, "provider is nil"},
		"nil logger":   {func() (*Password, error) { return New(nilLoggerProvider{}) }, "Logger() returned nil"},
		"two configs":  {func() (*Password, error) { return New(fakeProvider{}, Config{}, Config{}) }, "at most one Config"},
	} {
		_, err := tc.build()
		if !errors.Is(err, ErrInvalidConfig) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want ErrInvalidConfig naming %q", name, err, tc.want)
		}
	}
	if _, err := New(fakeProvider{}, Config{}); err != nil {
		t.Fatalf("one Config: %v, want accepted", err)
	}
}
