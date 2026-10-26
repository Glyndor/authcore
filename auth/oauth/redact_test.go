package oauth_test

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth"
	"github.com/Glyndor/authcore/auth/oauth/internal/oauthtest"
)

const redactTestSecret = "client-secret-0123456789abcdefghijkl"

func redactTestConfig() oauth.Config {
	return oauth.Config{
		ClientID: "id-1", ClientSecret: redactTestSecret, RedirectURL: "https://app.example.com/cb",
		Provider: oauth.Provider{Issuer: "https://idp.example.com", AuthURL: "https://idp.example.com/a"},
		Scopes:   []string{"openid", "email"},
	}
}

func TestConfigRenderingsOmitTheSecret(t *testing.T) {
	cfg := redactTestConfig()
	var nilCfg *oauth.Config
	for _, verb := range []string{"%v", "%+v", "%s", "%#v", "%q"} {
		for name, v := range map[string]any{"value": cfg, "pointer": &cfg} {
			out := fmt.Sprintf(verb, v)
			if strings.Contains(out, redactTestSecret) {
				t.Errorf("%s %s leaks the secret: %s", name, verb, out)
			}
			if !strings.Contains(out, "id-1") || !strings.Contains(out, "[redacted]") ||
				!strings.Contains(out, "idp.example.com") || !strings.Contains(out, "openid") {
				t.Errorf("%s %s lost a debugging field: %s", name, verb, out)
			}
		}
	}
	if got := fmt.Sprintf("%x", cfg); got != "%!x(oauth.Config)" {
		t.Errorf("%%x = %q", got)
	}
	if got := fmt.Sprintf("%v", nilCfg); got != "<nil>" {
		t.Errorf("nil %%v = %q", got)
	}
}

func TestConfigShowsWhichSecretSourceIsSet(t *testing.T) {
	public := oauth.Config{ClientID: "id-2"}
	if out := public.String(); !strings.Contains(out, `ClientSecret:""`) || !strings.Contains(out, `ClientSecretFunc:""`) {
		t.Errorf("public client: %s", out)
	}
	withFunc := oauth.Config{ClientSecretFunc: func(context.Context) (string, error) { return redactTestSecret, nil }}
	out := withFunc.GoString()
	if !strings.Contains(out, `ClientSecretFunc:"[redacted]"`) || strings.Contains(out, redactTestSecret) {
		t.Errorf("func client: %s", out)
	}
}

func TestConfigAndClientLogValues(t *testing.T) {
	cfg := redactTestConfig()
	var nilCfg *oauth.Config
	var nilClient *oauth.Client
	c := oauthtest.OAuth2Client(t, "https://idp.example.com/userinfo")
	var buf bytes.Buffer
	slog.New(slog.NewTextHandler(&buf, nil)).Info("x", "cfg", &cfg, "nilcfg", nilCfg, "client", c, "nilclient", nilClient)
	out := buf.String()
	if strings.Contains(out, redactTestSecret) || !strings.Contains(out, "nilcfg=<nil>") || !strings.Contains(out, "nilclient=<nil>") {
		t.Errorf("slog: %s", out)
	}
}

func TestClientRenderings(t *testing.T) {
	c := oauthtest.OAuth2Client(t, "https://idp.example.com/userinfo")
	var nilClient *oauth.Client
	for _, v := range []any{c, *c} {
		if out := fmt.Sprintf("%+v", v); !strings.HasPrefix(out, "oauth.Client{") {
			t.Errorf("%%+v = %s", out)
		}
		if out := fmt.Sprintf("%#v", v); !strings.HasPrefix(out, "&oauth.Client{") {
			t.Errorf("%%#v = %s", out)
		}
	}
	if got := nilClient.String(); got != "<nil>" {
		t.Errorf("nil String() = %q", got)
	}
	if got := nilClient.GoString(); got != "(*oauth.Client)(nil)" {
		t.Errorf("nil GoString() = %q", got)
	}
}
