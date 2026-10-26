// Command oauth is a runnable end-to-end example of authcore's OIDC / OAuth2
// client, a real two-route social-login flow you can point at a live provider.
//
// Configure it with environment variables and run:
//
//	OAUTH_PROVIDER=google \
//	OAUTH_CLIENT_ID=... OAUTH_CLIENT_SECRET=... \
//	go run ./examples/modules/oauth
//
// then open http://localhost:8080/login. Supported OAUTH_PROVIDER values:
// google, microsoft, apple, vercel (OIDC) and github, discord (plain OAuth2).
//
// Apple needs more than a client id and secret. The Apple "client secret" is a
// short-lived JWT signed with an ES256 key the Developer portal delivers once,
// so the example also reads:
//
//	APPLE_TEAM_ID            10-char team id, [A-Z0-9]
//	APPLE_KEY_ID             10-char key id, [A-Z0-9]
//	APPLE_PRIVATE_KEY_FILE   path to the .p8 file (PEM, "PRIVATE KEY")
//
// The Services ID's "Return URLs" allow-list is https-only, so a plain
// http://localhost callback cannot work with Apple. Register an https
// callback (or run the demo behind a TLS-terminating proxy) when targeting
// Apple.
package main

import (
	"log"
	"os"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/oauth"
)

func main() {
	auth, err := authcore.New(authcore.DefaultConfig())
	if err != nil {
		log.Fatalf("authcore: %v", err)
	}

	provider := env("OAUTH_PROVIDER", "google")
	cfg := oauth.Config{
		ClientID:     os.Getenv("OAUTH_CLIENT_ID"),
		ClientSecret: os.Getenv("OAUTH_CLIENT_SECRET"),
		RedirectURL:  env("OAUTH_REDIRECT_URL", "http://localhost:8080/callback"),
	}
	switch provider {
	case "google":
		cfg.Provider = oauth.Google()
	case "microsoft":
		// A specific tenant id is required: the multi-tenant aliases
		// (common/organizations/consumers) fail exact-issuer validation.
		tenant := env("OAUTH_TENANT", "")
		switch tenant {
		case "", "common", "organizations", "consumers":
			log.Fatal("set OAUTH_TENANT to a specific Microsoft tenant id (a GUID); the common/organizations aliases do not pass exact-issuer validation")
		}
		p, err := oauth.Microsoft(tenant)
		if err != nil {
			log.Fatalf("microsoft preset: %v", err)
		}
		cfg.Provider = p
	case "apple":
		// Apple hands out the .p8 once, from the Developer portal: keep it on
		// disk, not in the environment, and never log it. The three IDs are
		// the only things safe to log if a read fails.
		teamID := os.Getenv("APPLE_TEAM_ID")
		keyID := os.Getenv("APPLE_KEY_ID")
		keyFile := os.Getenv("APPLE_PRIVATE_KEY_FILE")
		if teamID == "" || keyID == "" || keyFile == "" {
			log.Fatal("set APPLE_TEAM_ID, APPLE_KEY_ID and APPLE_PRIVATE_KEY_FILE (path to the .p8) for OAUTH_PROVIDER=apple")
		}
		//nolint:gosec // G304: the .p8 path comes from APPLE_PRIVATE_KEY_FILE set by the operator on the demo host. The operator chose it.
		p8, err := os.ReadFile(keyFile)
		if err != nil {
			log.Fatalf("APPLE_PRIVATE_KEY_FILE: %v", err)
		}
		secret, err := oauth.AppleClientSecret(teamID, keyID, cfg.ClientID, p8)
		if err != nil {
			log.Fatalf("apple client secret: %v", err)
		}
		// Apple has no static client secret. Refuse one rather than drop it
		// silently: it means the environment was set up for another provider.
		if cfg.ClientSecret != "" {
			log.Fatal("unset OAUTH_CLIENT_SECRET for OAUTH_PROVIDER=apple: the secret is signed from the .p8 key")
		}
		cfg.ClientSecretFunc = secret
		cfg.Provider = oauth.Apple()
	case "vercel":
		cfg.Provider = oauth.Vercel()
	case "github":
		cfg.Provider = oauth.GitHub()
		cfg.Scopes = []string{"read:user", "user:email"}
	case "discord":
		cfg.Provider = oauth.Discord()
		cfg.Scopes = []string{"identify", "email"}
	default:
		log.Fatalf("unknown OAUTH_PROVIDER %q (want google|microsoft|apple|vercel|github|discord)", provider)
	}

	mod, err := oauth.New(auth, cfg)
	if err != nil {
		log.Fatalf("oauth: %v", err)
	}
	oidc := provider == "google" || provider == "microsoft" || provider == "apple" || provider == "vercel"

	handler := newHandler(mod, oidc, provider == "apple")

	addr := env("OAUTH_ADDR", ":8080")
	srv := newServer(addr, handler)
	log.Printf("oauth example (provider=%s) listening on %s — open http://localhost%s/login", provider, addr, addr)
	log.Fatal(srv.ListenAndServe())
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
