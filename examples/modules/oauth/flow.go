package main

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Glyndor/authcore/auth/oauth"
)

// maxCallbackBody caps the form an Apple callback POSTs back. It carries a
// code, a state and at most a small user object.
const maxCallbackBody = 16 << 10

const flowCookieName = "oauthflow"

// flow holds what the two handlers share. crossSite is true for a provider
// whose callback arrives as a cross-site POST (Apple, response_mode=form_post).
type flow struct {
	mod       *oauth.Client
	oidc      bool
	crossSite bool
}

// newHandler builds the two-route handler. Only the routes the flow needs are
// registered, with their method: /login and /callback are GET, and /callback
// also takes a POST for a form_post provider. Everything else is a 404 or 405.
// Every response is uncacheable, because the callback answers with an identity.
func newHandler(mod *oauth.Client, oidc, crossSite bool) http.Handler {
	f := &flow{mod: mod, oidc: oidc, crossSite: crossSite}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /login", f.login)
	mux.HandleFunc("GET /callback", f.callback)
	if crossSite {
		mux.HandleFunc("POST /callback", f.callback)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		mux.ServeHTTP(w, r)
	})
}

// newServer wraps h in an http.Server with every timeout set. The write
// timeout leaves room for the token exchange and the profile request.
func newServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      40 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
}

// login starts the flow: build the redirect, persist the per-request secrets.
// DEMO ONLY: a plain cookie holds them; in production sign it (HttpOnly+Secure)
// or use a server-side session. The redirect target comes from the library and
// the configuration, never from a request parameter.
func (f *flow) login(w http.ResponseWriter, r *http.Request) {
	req, err := f.mod.AuthCodeURL()
	if err != nil {
		log.Printf("auth code url: %v", err)
		http.Error(w, "could not start the login", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, f.cookie(r, req.State+"|"+req.Nonce+"|"+req.Verifier, 300))
	http.Redirect(w, r, req.URL, http.StatusFound)
}

// callback finishes the flow: check state, exchange the code, then validate the
// ID token (OIDC) or fetch the profile (OAuth2). The flow cookie is spent on
// the first call, whatever its outcome.
func (f *flow) callback(w http.ResponseWriter, r *http.Request) {
	state, nonce, verifier, ok := readFlowCookie(r)
	http.SetCookie(w, f.cookie(r, "", -1))
	if !ok || state == "" || verifier == "" || (f.oidc && nonce == "") {
		http.Error(w, "missing or bad flow cookie", http.StatusBadRequest)
		return
	}

	params, err := callbackParams(w, r)
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "bad callback", http.StatusBadRequest)
		return
	}
	got, single := one(params, "state")
	if !single || subtle.ConstantTimeCompare([]byte(got), []byte(state)) != 1 {
		http.Error(w, "state mismatch", http.StatusBadRequest)
		return
	}

	// The provider reports a refusal in "error". Neither it nor its description
	// is echoed to the page or written to the log: both are text the caller of
	// the callback chose.
	if len(params["error"]) > 0 {
		log.Print("provider refused the authorization")
		http.Error(w, "authorization was not granted", http.StatusUnauthorized)
		return
	}
	code, single := one(params, "code")
	if !single || code == "" {
		http.Error(w, "bad callback", http.StatusBadRequest)
		return
	}

	tok, err := f.mod.Exchange(r.Context(), code, verifier)
	if err != nil {
		http.Error(w, "token exchange failed", http.StatusUnauthorized)
		return
	}

	var identity any
	if f.oidc {
		identity, err = f.mod.VerifyIDToken(r.Context(), tok.IDToken, nonce)
	} else {
		identity, err = f.mod.UserInfo(r.Context(), tok.AccessToken)
	}
	if err != nil {
		http.Error(w, "identity check failed", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(identity)
}

// callbackParams returns the parameters the provider sent: the query of a GET,
// or the body of the POST a form_post provider makes. The other source is
// ignored, so a request cannot supply a value through the channel the provider
// does not use.
func callbackParams(w http.ResponseWriter, r *http.Request) (url.Values, error) {
	if r.Method != http.MethodPost {
		return r.URL.Query(), nil
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxCallbackBody)
	if err := r.ParseForm(); err != nil {
		return nil, err
	}
	return r.PostForm, nil
}

// one returns the value of key and whether it was sent exactly once. A
// repeated parameter is ambiguous, and which copy a proxy or a provider reads
// is not defined, so it counts as absent.
func one(v url.Values, key string) (string, bool) {
	values := v[key]
	if len(values) != 1 {
		return "", false
	}
	return values[0], true
}

// cookie builds the flow cookie. crossSite providers need SameSite=None, which
// browsers only honour with Secure, so Secure is forced on for them whatever
// the transport. For every other provider the cookie is SameSite=Lax and
// Secure follows the request, so a plain-http localhost run still works. The
// path is the callback alone: no other route of the host receives it.
func (f *flow) cookie(r *http.Request, value string, maxAge int) *http.Cookie {
	c := &http.Cookie{
		Name:     flowCookieName,
		Value:    base64.RawURLEncoding.EncodeToString([]byte(value)),
		Path:     "/callback",
		HttpOnly: true,
		MaxAge:   maxAge,
	}
	if f.crossSite {
		c.SameSite = http.SameSiteNoneMode
		c.Secure = true
	} else {
		c.SameSite = http.SameSiteLaxMode
		c.Secure = isSecureRequest(r)
	}
	return c
}

// isSecureRequest reports whether the request reached us over TLS — directly or
// via a TLS-terminating proxy. The cookie is marked Secure whenever it is, so it
// is never sent in cleartext in production; on a plain-http localhost dev run it
// is not, so the demo still works.
func isSecureRequest(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func readFlowCookie(r *http.Request) (state, nonce, verifier string, ok bool) {
	c, err := r.Cookie(flowCookieName)
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
