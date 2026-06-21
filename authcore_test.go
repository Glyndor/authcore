package authcore_test

import (
	"errors"
	"testing"
	"time"

	"github.com/Glyndor/authcore"
)

// ---- New() ------------------------------------------------------------------

func TestNew_defaultConfigSucceeds(t *testing.T) {
	cfg := authcore.DefaultConfig()
	cfg.KeysDir = t.TempDir()

	_, err := authcore.New(cfg)
	if err != nil {
		t.Fatalf("New(DefaultConfig) error = %v", err)
	}
}

func TestNew_emptyConfigSucceedsBecauseDefaultsAreApplied(t *testing.T) {
	// Config{} has Timezone=nil, but applyDefaults fills it with time.UTC
	// before validation runs — New must not return an error.
	cfg := authcore.Config{KeysDir: t.TempDir()}
	_, err := authcore.New(cfg)
	if err != nil {
		t.Fatalf("New(Config{}) error = %v; applyDefaults should have filled zero values", err)
	}
}

func TestNew_badKeysDirReturnsErrInvalidConfig(t *testing.T) {
	cfg := authcore.DefaultConfig()
	cfg.KeysDir = string([]byte{0}) // null byte makes every OS reject the path

	// validateConfig now checks writability early, so a bad KeysDir is caught
	// as ErrInvalidConfig rather than ErrKeyManager.
	_, err := authcore.New(cfg)
	if !errors.Is(err, authcore.ErrInvalidConfig) {
		t.Errorf("expected ErrInvalidConfig, got %v", err)
	}
}

// ---- Config() ---------------------------------------------------------------

func TestConfig_returnsActiveValues(t *testing.T) {
	bogota, err := time.LoadLocation("America/Bogota")
	if err != nil {
		t.Fatalf("load location: %v", err)
	}

	cfg := authcore.DefaultConfig()
	cfg.KeysDir = t.TempDir()
	cfg.Timezone = bogota
	cfg.EnableLogs = false

	ac, err := authcore.New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	got := ac.Config()
	if got.Timezone.String() != bogota.String() {
		t.Errorf("Config().Timezone = %v, want %v", got.Timezone, bogota)
	}
	if got.EnableLogs {
		t.Error("Config().EnableLogs = true, want false")
	}
}

// ---- Logger() ---------------------------------------------------------------

func TestLogger_returnsNonNil(t *testing.T) {
	cfg := authcore.DefaultConfig()
	cfg.KeysDir = t.TempDir()
	cfg.EnableLogs = false

	ac, err := authcore.New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if ac.Logger() == nil {
		t.Error("Logger() returned nil")
	}
}

func TestLogger_customLoggerIsForwarded(t *testing.T) {
	called := false
	spy := &spyLogger{onInfo: func() { called = true }}

	cfg := authcore.DefaultConfig()
	cfg.KeysDir = t.TempDir()
	cfg.Logger = spy

	_, err := authcore.New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if !called {
		t.Error("custom logger.Info was never called during initialisation")
	}
}

func TestLogger_stdLoggerUsedWhenEnableLogsTrue(t *testing.T) {
	cfg := authcore.DefaultConfig() // EnableLogs = true, no custom Logger
	cfg.KeysDir = t.TempDir()

	// New() must not panic or error when the stdlib logger is active.
	_, err := authcore.New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
}

func TestLogger_noopLoggerUsedWhenEnableLogsFalse(t *testing.T) {
	cfg := authcore.DefaultConfig()
	cfg.KeysDir = t.TempDir()
	cfg.EnableLogs = false

	// New() must not panic or error when the noop logger is active.
	_, err := authcore.New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
}

// ---- Keys() -----------------------------------------------------------------

func TestKeys_returnsNonNil(t *testing.T) {
	cfg := authcore.DefaultConfig()
	cfg.KeysDir = t.TempDir()
	cfg.EnableLogs = false

	ac, err := authcore.New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	k := ac.Keys()
	if k == nil {
		t.Fatal("Keys() returned nil")
	}
	if len(k.PrivateKey()) == 0 {
		t.Error("Keys().PrivateKey() is empty")
	}
	if len(k.PublicKey()) == 0 {
		t.Error("Keys().PublicKey() is empty")
	}
	if len(k.RefreshSecret()) == 0 {
		t.Error("Keys().RefreshSecret() is empty")
	}
	if k.KeyID() == "" {
		t.Error("Keys().KeyID() is empty")
	}
}

// ---- DefaultConfig() --------------------------------------------------------

func TestDefaultConfig_values(t *testing.T) {
	cfg := authcore.DefaultConfig()

	if !cfg.EnableLogs {
		t.Error("DefaultConfig().EnableLogs = false, want true")
	}
	if cfg.Timezone != time.UTC {
		t.Errorf("DefaultConfig().Timezone = %v, want time.UTC", cfg.Timezone)
	}
	if cfg.KeysDir != ".authcore" {
		t.Errorf("DefaultConfig().KeysDir = %q, want %q", cfg.KeysDir, ".authcore")
	}
	if cfg.Logger != nil {
		t.Error("DefaultConfig().Logger must be nil")
	}
}

// ---- helpers ----------------------------------------------------------------

type spyLogger struct{ onInfo func() }

func (s *spyLogger) Debug(string, ...any) {}
func (s *spyLogger) Info(_ string, _ ...any) {
	if s.onInfo != nil {
		s.onInfo()
	}
}
func (s *spyLogger) Warn(string, ...any)  {}
func (s *spyLogger) Error(string, ...any) {}
