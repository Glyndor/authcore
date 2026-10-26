package username

import (
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/username"
)

type infoLog struct {
	mu    sync.Mutex
	lines []string
}

func (*infoLog) Debug(string, ...any) {}
func (*infoLog) Warn(string, ...any)  {}
func (*infoLog) Error(string, ...any) {}
func (l *infoLog) Info(msg string, _ ...any) {
	l.mu.Lock()
	l.lines = append(l.lines, msg)
	l.mu.Unlock()
}

func provider(t *testing.T, log authcore.Logger) authcore.Provider {
	t.Helper()
	cfg := authcore.DefaultConfig()
	cfg.KeysDir = t.TempDir()
	cfg.Logger = log
	ac, err := authcore.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return ac
}

func TestHostile_Username_constructionIsAnnouncedOnTheProvidersLogger(t *testing.T) {
	rec := &infoLog{}
	p := provider(t, rec)
	rec.lines = nil
	if _, err := username.New(p); err != nil {
		t.Fatal(err)
	}
	if len(rec.lines) != 1 || !strings.Contains(rec.lines[0], "username: module initialised") {
		t.Fatalf("info lines = %q, want one username initialisation line", rec.lines)
	}
}

func TestHostile_Username_aRefusedConfigNamesItsReason(t *testing.T) {
	_, err := username.NewWithConfig(provider(t, &infoLog{}), username.Config{MinLength: 9, MaxLength: 4})
	if !errors.Is(err, username.ErrInvalidConfig) {
		t.Fatalf("err = %v, want ErrInvalidConfig", err)
	}
	cause := errors.Unwrap(err)
	if cause == nil || !strings.Contains(cause.Error(), "max length") {
		t.Fatalf("errors.Unwrap = %v, want the specific rule that failed", cause)
	}
}
