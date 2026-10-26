package leak

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth"
	"github.com/Glyndor/authcore/tests/hostile/misuse/hostiletest"
)

const clientSecret = "client-secret-0123456789abcdefghijkl"

// The OAuth client secret must not reach a log line through the config or the
// client built from it, while the fields that help debugging stay visible.
func TestHostile_Leak_oauthConfigAndClientStayQuiet(t *testing.T) {
	e := hostiletest.NewEnv(t)
	cfg := oauth.Config{
		ClientID: "client-id-1", ClientSecret: clientSecret,
		RedirectURL: "https://app.example.com/cb", Provider: oauth.Google(),
	}
	cl, err := oauth.New(e.AC, cfg)
	if err != nil {
		t.Fatal(err)
	}
	fromFunc := oauth.Config{
		ClientID: "client-id-2", RedirectURL: "https://app.example.com/cb", Provider: oauth.Google(),
		ClientSecretFunc: func(context.Context) (string, error) { return clientSecret, nil },
	}
	var nilCfg *oauth.Config
	var nilClient *oauth.Client
	checkAll(t, []target{
		{"oauth.Config value", cfg}, {"oauth.Config pointer", &cfg}, {"oauth.Config nil", nilCfg},
		{"oauth.Config func", fromFunc},
		{"oauth.Client pointer", cl}, {"oauth.Client value", *cl}, {"oauth.Client nil", nilClient},
	}, []byte(clientSecret))

	for _, v := range []any{cfg, &cfg, cl, *cl} {
		out := fmt.Sprintf("%+v", v)
		for _, want := range []string{"client-id-1", "accounts.google.com", `ClientSecret:"[redacted]"`} {
			if !strings.Contains(out, want) {
				t.Errorf("%T %%+v lost %q: %s", v, want, out)
			}
		}
	}
}
