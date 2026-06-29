# OIDC login

`auth/oauth` is an OpenID Connect **client** — "log in with Google / Microsoft /
any OIDC provider". It implements the security-critical mechanics: Authorization
Code flow with **PKCE (S256)**, an unguessable `state` and `nonce`, and strict
**ID-token validation** (signature against the provider's JWKS, plus issuer,
audience, expiry, and nonce). It is a client only — authcore is not an OAuth
server. It stores nothing and runs no HTTP server; you own the two routes.

> [!NOTE]
> Two kinds of provider are supported. **OIDC** providers (Google, Microsoft,
> Auth0, Keycloak…) issue an ID token — validate it with `VerifyIDToken`.
> **Plain-OAuth2** providers (GitHub, Discord…) issue no ID token — fetch the
> profile with `UserInfo` instead. The authorization + PKCE + exchange steps are
> identical for both.

## Providers

Four presets ship; practically any provider works beyond them.

| Provider | Kind | How |
|---|---|---|
| Google | OIDC | `oauth.Google()` |
| Microsoft (Azure AD) | OIDC | `oauth.Microsoft(tenant)` |
| GitHub | OAuth2 | `oauth.GitHub()` |
| Discord | OAuth2 | `oauth.Discord()` |
| **Any OIDC** (Apple, Okta, Auth0, GitLab, Cognito, Keycloak…) | OIDC | `oauth.Discover(ctx, issuer, nil)` |
| **Any OAuth2** (Facebook, Spotify, Twitch…) | OAuth2 | `oauth.Provider{AuthURL, TokenURL, UserInfoURL}` |

Identity is `VerifyIDToken` for OIDC, `UserInfo` for OAuth2.

## Setup

```go
auth, _ := authcore.New(authcore.DefaultConfig())
mod, err := oauth.New(auth, oauth.Config{
    ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
    ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
    RedirectURL:  "https://app.example.com/auth/callback",
    Provider:     oauth.Google(), // or oauth.Microsoft("<your-tenant-id>"), or a custom Provider
})
```

### Any OIDC provider — discovery

You don't need a preset or hand-written endpoints. `Discover` reads the
provider's `.well-known/openid-configuration` and builds the `Provider` for you
— always-current endpoints, works for Apple, Okta, Auth0, GitLab, Cognito,
Keycloak, any standard OIDC issuer:

```go
p, err := oauth.Discover(ctx, "https://accounts.google.com", nil)
if err != nil { log.Fatal(err) }
mod, _ := oauth.New(auth, oauth.Config{ClientID: id, ClientSecret: secret, RedirectURL: cb, Provider: p})
```

Discovery enforces that the document's issuer matches the one you asked for, so
a substituted document cannot redirect the client to attacker endpoints.

Or hand-write the four endpoints if you prefer:

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
if subtle.ConstantTimeCompare([]byte(r.FormValue("state")), []byte(savedState)) != 1 {
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

## Plain-OAuth2 providers (GitHub, Discord, …)

Providers that issue no ID token use the same start/exchange steps, then
`UserInfo` instead of `VerifyIDToken`:

```go
mod, _ := oauth.New(auth, oauth.Config{
    ClientID: id, ClientSecret: secret,
    RedirectURL: "https://app.example.com/auth/callback",
    Provider:    oauth.GitHub(),            // or oauth.Discord()
    Scopes:      []string{"read:user", "user:email"}, // provider's own scopes
})

// Callback: check state, exchange, then fetch the profile.
tok, _ := mod.Exchange(r.Context(), code, savedVerifier)
info, err := mod.UserInfo(r.Context(), tok.AccessToken)
if err != nil { /* 401 */ }
// info is the provider's raw JSON: GitHub "id"/"login", Discord "id"/"username".
// Key your account on (provider, info["id"]).
```

`UserInfo` sends the access token as a Bearer credential, caps the response, and
returns the decoded JSON. There is no ID token to validate here — identity is
whatever the userinfo endpoint returns, so trust only the provider's stable id.

> Custom OAuth2 provider: set `Provider{AuthURL, TokenURL, UserInfoURL}` (no
> issuer/JWKS). A provider with neither issuer+JWKS nor a userinfo URL is
> rejected at `New` — it could not identify the user.

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
