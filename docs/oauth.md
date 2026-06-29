# OIDC login

`auth/oauth` is an OpenID Connect **client** — "log in with Google / Microsoft /
any OIDC provider". It implements the security-critical mechanics: Authorization
Code flow with **PKCE (S256)**, an unguessable `state` and `nonce`, and strict
**ID-token validation** (signature against the provider's JWKS, plus issuer,
audience, expiry, and nonce). It is a client only — authcore is not an OAuth
server. It stores nothing and runs no HTTP server; you own the two routes.

> [!NOTE]
> This covers OIDC providers (Google, Microsoft, Auth0, Keycloak…) that issue an
> ID token. Pure-OAuth2 providers that don't (e.g. GitHub) need a userinfo
> fetch and are not yet covered.

## Setup

```go
auth, _ := authcore.New(authcore.DefaultConfig())
mod, err := oauth.New(auth, oauth.Config{
    ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
    ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
    RedirectURL:  "https://app.example.com/auth/callback",
    Provider:     oauth.Google(), // or oauth.Microsoft("common"), or a custom Provider
})
```

A custom provider is just four endpoints (from its `.well-known/openid-configuration`):

```go
Provider: oauth.Provider{
    Issuer:   "https://id.example.com",
    AuthURL:  "https://id.example.com/authorize",
    TokenURL: "https://id.example.com/token",
    JWKSURL:  "https://id.example.com/jwks",
}
```

## The two routes

**Start** — build the redirect and persist the three secrets where only this
browser can return them (a short-lived `HttpOnly` signed cookie or the session):

```go
req, _ := mod.AuthCodeURL()
saveToCookie(w, req.State, req.Nonce, req.Verifier) // all three
http.Redirect(w, r, req.URL, http.StatusFound)
```

**Callback** — check `state`, exchange the code, validate the ID token:

```go
if r.FormValue("state") != savedState {
    http.Error(w, "bad state", http.StatusBadRequest) // CSRF / stale
    return
}
tok, err := mod.Exchange(r.Context(), r.FormValue("code"), savedVerifier)
if err != nil { /* 401 */ }

claims, err := mod.VerifyIDToken(r.Context(), tok.IDToken, savedNonce)
if err != nil { /* 401 — never show the reason */ }

// claims.Subject is the stable user id AT THIS PROVIDER.
// Key your account on (claims.Issuer, claims.Subject), not on email.
```

## What it guarantees

- **PKCE S256 always.** The `plain` method is never offered, so a downgrade
  cannot strip it. Works for public clients (no secret) too.
- **ID-token signature** is checked against the provider's JWKS, fetched and
  cached (1 h), refreshed automatically on an unknown `kid` so key rotation just
  works. Only asymmetric algorithms (RS/PS/ES) are accepted — `none` and HMAC
  are refused, closing the algorithm-confusion forgery.
- **Issuer, audience, expiry, and nonce** are all enforced. A mismatch fails
  closed with `ErrIDTokenInvalid`.

## What is yours

Sessions, cookies, CSRF on your own routes, and where you persist the per-request
secrets — same as the rest of authcore. See the
[secure login recipe](secure-login.md).
