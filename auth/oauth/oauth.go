// Package oauth is an OpenID Connect (OIDC) client for authcore — "log in with
// Google / Microsoft / any OIDC provider".
//
// It implements the security-critical mechanics you only get right once:
// Authorization Code flow with PKCE (S256), an unguessable state and nonce, and
// strict ID-token validation (signature against the provider's JWKS, plus
// issuer, audience, expiry, and nonce). It is a client only — authcore does not
// act as an OAuth server. It stores nothing and runs no HTTP server; you own
// the two routes and where you persist the per-request secrets.
//
// # Flow
//
//	mod, _ := oauth.New(auth, oauth.Config{
//	    ClientID: id, ClientSecret: secret,
//	    RedirectURL: "https://app.example.com/callback",
//	    Provider: oauth.Google(),
//	})
//
//	// 1. Start: build the redirect and persist the returned secrets
//	//    (state, nonce, verifier) in a short-lived signed cookie or the session.
//	req, _ := mod.AuthCodeURL()
//	saveToCookie(w, req.State, req.Nonce, req.Verifier)
//	http.Redirect(w, r, req.URL, http.StatusFound)
//
//	// 2. Callback: check state, exchange the code, validate the ID token.
//	if savedState == "" || subtle.ConstantTimeCompare([]byte(r.FormValue("state")), []byte(savedState)) != 1 { return /* 400 */ }
//	tok, _ := mod.Exchange(r.Context(), r.FormValue("code"), savedVerifier)
//	claims, err := mod.VerifyIDToken(r.Context(), tok.IDToken, savedNonce)
//	if err != nil { return /* 401 */ }
//	// claims.Subject is the stable user id at this provider; claims.Email etc.
package oauth
