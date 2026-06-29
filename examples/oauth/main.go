// Command oauth is a runnable end-to-end example of authcore's OIDC / OAuth2
// client — a real two-route social-login flow you can point at a live provider.
//
// Configure it with environment variables and run:
//
//	OAUTH_PROVIDER=google \
//	OAUTH_CLIENT_ID=... OAUTH_CLIENT_SECRET=... \
//	go run ./examples/oauth
//
// then open http://localhost:8080/login. Supported OAUTH_PROVIDER values:
// google, microsoft (OIDC), github, discord (plain OAuth2).
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
			log.Fatal("set OAUTH_TENANT to a specific Microsoft tenant id (GUID or verified domain); the common/organizations aliases do not pass exact-issuer validation")
		}
		cfg.Provider = oauth.Microsoft(tenant)
	case "github":
		cfg.Provider = oauth.GitHub()
		cfg.Scopes = []string{"read:user", "user:email"}
	case "discord":
		cfg.Provider = oauth.Discord()
		cfg.Scopes = []string{"identify", "email"}
	default:
		log.Fatalf("unknown OAUTH_PROVIDER %q (want google|microsoft|github|discord)", provider)
	}

	mod, err := oauth.New(auth, cfg)
	if err != nil {
		log.Fatalf("oauth: %v", err)
	}
	oidc := provider == "google" || provider == "microsoft"

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
		setFlowCookie(w, r, req.State+"|"+req.Nonce+"|"+req.Verifier)
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

func setFlowCookie(w http.ResponseWriter, r *http.Request, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "oauthflow",
		Value:    base64.RawURLEncoding.EncodeToString([]byte(value)),
		Path:     "/",
		HttpOnly: true,
		Secure:   isSecureRequest(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   300,
	})
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
