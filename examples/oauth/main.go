// Command oauth is a runnable end-to-end example of authcore's OIDC / OAuth2
// client, a real two-route social-login flow you can point at a live provider.
//
// Configure it with environment variables and run:
//
//	OAUTH_PROVIDER=google \
//	OAUTH_CLIENT_ID=... OAUTH_CLIENT_SECRET=... \
//	go run ./examples/oauth
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
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

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

	mux := http.NewServeMux()

	// /login starts the flow: build the redirect, persist the per-request
	// secrets. DEMO ONLY: a plain cookie holds them; in production sign it
	// (HttpOnly+Secure) or use a server-side session.
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		req, err := mod.AuthCodeURL()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		setFlowCookie(w, r, req.State+"|"+req.Nonce+"|"+req.Verifier, provider == "apple")
		http.Redirect(w, r, req.URL, http.StatusFound)
	})

	// /callback finishes it: check state, exchange the code, then validate the
	// ID token (OIDC) or fetch the profile (OAuth2).
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		state, nonce, verifier, ok := readFlowCookie(r)
		if !ok {
			http.Error(w, "missing or bad flow cookie", http.StatusBadRequest)
			return
		}
		if subtle.ConstantTimeCompare([]byte(r.FormValue("state")), []byte(state)) != 1 {
			http.Error(w, "state mismatch", http.StatusBadRequest)
			return
		}

		tok, err := mod.Exchange(r.Context(), r.FormValue("code"), verifier)
		if err != nil {
			http.Error(w, "token exchange failed", http.StatusUnauthorized)
			return
		}

		var identity any
		if oidc {
			identity, err = mod.VerifyIDToken(r.Context(), tok.IDToken, nonce)
		} else {
			identity, err = mod.UserInfo(r.Context(), tok.AccessToken)
		}
		if err != nil {
			http.Error(w, "identity check failed", http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(identity)
	})

	addr := env("OAUTH_ADDR", ":8080")
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("oauth example (provider=%s) listening on %s — open http://localhost%s/login", provider, addr, addr)
	log.Fatal(srv.ListenAndServe())
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// setFlowCookie persists the per-request OAuth state, nonce and PKCE verifier
// in a short-lived cookie. crossSite=true is for providers whose callback
// arrives as a cross-site POST (Apple, via response_mode=form_post): a Lax or
// Strict cookie is dropped on such a POST and the callback then fails because
// the saved state is missing. The cross-site form requires SameSite=None and a
// Secure attribute, so when crossSite is true the Secure flag is forced on
// regardless of the transport the request reached us over. For every other
// provider the Secure flag follows the request so a plain-http localhost dev
// run still works.
func setFlowCookie(w http.ResponseWriter, r *http.Request, value string, crossSite bool) {
	cookie := &http.Cookie{
		Name:     "oauthflow",
		Value:    base64.RawURLEncoding.EncodeToString([]byte(value)),
		Path:     "/",
		HttpOnly: true,
		MaxAge:   300,
	}
	if crossSite {
		cookie.SameSite = http.SameSiteNoneMode
		cookie.Secure = true
	} else {
		cookie.SameSite = http.SameSiteLaxMode
		cookie.Secure = isSecureRequest(r)
	}
	http.SetCookie(w, cookie)
}

// isSecureRequest reports whether the request reached us over TLS — directly or
// via a TLS-terminating proxy. The cookie is marked Secure whenever it is, so it
// is never sent in cleartext in production; on a plain-http localhost dev run it
// is not, so the demo still works.
func isSecureRequest(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func readFlowCookie(r *http.Request) (state, nonce, verifier string, ok bool) {
	c, err := r.Cookie("oauthflow")
	if err != nil {
		return "", "", "", false
	}
	raw, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return "", "", "", false
	}
	parts := strings.SplitN(string(raw), "|", 3)
	if len(parts) != 3 {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[2], true
}
