package oauth_test

import (
	"errors"
	"testing"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/oauth"
	"github.com/Glyndor/authcore/auth/oauth/internal/oauthtest"
)

type noLogger struct{ oauthtest.FakeProvider }

func (noLogger) Logger() authcore.Logger { return nil }

func TestNew_rejectsAnUnusableProvider(t *testing.T) {
	cfg := oauth.Config{ClientID: "x", RedirectURL: "https://app.example/cb", Provider: oauth.Google()}
	for name, p := range map[string]authcore.Provider{"nil": nil, "no logger": noLogger{}} {
		if _, err := oauth.New(p, cfg); !errors.Is(err, oauth.ErrInvalidConfig) {
			t.Errorf("%s: got %v, want ErrInvalidConfig", name, err)
		}
	}
}
