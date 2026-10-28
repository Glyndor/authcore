package email

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/email"
	"github.com/Glyndor/authcore/tests/hostile/identity/hostiletest"
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

func TestHostile_Email_theMXCacheKeepsResultsForFiveMinutes(t *testing.T) {
	if email.DefaultCacheTTL != 5*time.Minute {
		t.Fatalf("DefaultCacheTTL = %v, want 5m0s as documented", email.DefaultCacheTTL)
	}
}

func TestHostile_Email_plusAddressingPolicyAppliesToEveryLocalPart(t *testing.T) {
	strict := hostiletest.NewEmail(t, email.Config{RejectPlusAddressing: true})
	lax := hostiletest.NewEmail(t)
	for _, addr := range []string{"+@example.com", "a+b@example.com", "+tag@example.com"} {
		if got, err := lax.ValidateAndNormalize(addr); err != nil || got != addr {
			t.Errorf("default policy %q: %q, %v; plus-addressing is accepted unless asked otherwise", addr, got, err)
		}
		if _, err := strict.ValidateAndNormalize(addr); !errors.Is(err, email.ErrInvalidEmail) || !strings.Contains(err.Error(), "plus-addressing") {
			t.Errorf("strict policy %q: err = %v, want ErrInvalidEmail for plus-addressing", addr, err)
		}
	}
}

func TestHostile_Email_constructionIsAnnouncedOnTheProvidersLogger(t *testing.T) {
	rec := &infoLog{}
	cfg := authcore.DefaultConfig()
	cfg.KeysDir = t.TempDir()
	cfg.Logger = rec
	ac, err := authcore.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	rec.lines = nil
	if _, err := email.New(ac); err != nil {
		t.Fatal(err)
	}
	if len(rec.lines) != 1 || !strings.Contains(rec.lines[0], "email: module initialised") {
		t.Fatalf("info lines = %q, want one email initialisation line", rec.lines)
	}
}
