package password_test

import (
	"testing"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/password"
)

type normalizationProvider struct{}

func (normalizationProvider) Config() authcore.Config { return authcore.DefaultConfig() }
func (normalizationProvider) Keys() authcore.Keys     { return nil }
func (normalizationProvider) Logger() authcore.Logger { return normalizationLogger{} }

type normalizationLogger struct{}

func (normalizationLogger) Debug(string, ...any) {}
func (normalizationLogger) Info(string, ...any)  {}
func (normalizationLogger) Warn(string, ...any)  {}
func (normalizationLogger) Error(string, ...any) {}

func TestVerifyMatchesCanonicalUnicodeRegardlessOfRegistrationSpelling(t *testing.T) {
	t.Parallel()
	mod, err := password.New(normalizationProvider{}, password.Config{Memory: 8192, Iterations: 1, Parallelism: 1})
	if err != nil {
		t.Fatal(err)
	}
	spellings := []string{"MotDePasseÉ1!", "MotDePasseE\u03011!"}
	for _, registered := range spellings {
		hash, err := mod.Hash(registered)
		if err != nil {
			t.Fatal(err)
		}
		for _, submitted := range spellings {
			if ok, err := mod.Verify(submitted, hash); !ok || err != nil {
				t.Fatalf("canonically equivalent password did not verify: ok=%v, err=%v", ok, err)
			}
		}
		if ok, err := mod.Verify("MotDePasseE1!", hash); ok || err != nil {
			t.Fatalf("removing the accent must not verify: ok=%v, err=%v", ok, err)
		}
	}
}
