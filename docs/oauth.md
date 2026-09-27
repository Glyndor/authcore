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
> identical for both. Discord publishes a discovery document too; see below.

## Providers

Five presets ship; practically any provider works beyond them.

| Provider | Kind | How |
|---|---|---|
| Apple | OIDC | `oauth.Apple()` |
| Google | OIDC | `oauth.Google()` |
| Microsoft (Azure AD) | OIDC | `oauth.Microsoft(tenant)` |
| GitHub | OAuth2 | `oauth.GitHub()` |
| Discord | OAuth2 (preset) / OIDC via Discover | `oauth.Discord()` |
| **Any OIDC** (Okta, Auth0, GitLab, Cognito, Keycloak…) | OIDC | `oauth.Discover(ctx, issuer, nil)` |
| **Any OAuth2** (Facebook, Spotify, Twitch…) | OAuth2 | `oauth.Provider{AuthURL, TokenURL, UserInfoURL}` |

Identity is `VerifyIDToken` for OIDC, `UserInfo` for OAuth2.

## Setup

```go
auth, err := authcore.New(authcore.DefaultConfig())
if err != nil { /* startup error */ }

provider := oauth.Google()
// A single Azure AD tenant instead. Microsoft refuses anything but a tenant id GUID:
//   provider, err = oauth.Microsoft(os.Getenv("AZURE_TENANT_ID"))
//   if err != nil { /* startup error */ }

mod, err := oauth.New(auth, oauth.Config{
    ClientID:     os.Getenv("OAUTH_CLIENT_ID"),
    ClientSecret: os.Getenv("OAUTH_CLIENT_SECRET"),
    RedirectURL:  "https://app.example.com/auth/callback",
    Provider:     provider, // or a hand-built Provider
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

### Multi-tenant providers (Azure AD common)

By default the ID token's `iss` must match `Provider.Issuer` exactly. A
multi-tenant provider gives each user a token whose issuer carries their own
tenant id, so no fixed string matches. Set `Config.IssuerValidator` to accept
the issuer by predicate instead:

```go
cfg := oauth.Config{
    ClientID: id, ClientSecret: secret, RedirectURL: cb,
    Provider: oauth.Provider{
        AuthURL:  "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        TokenURL: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        JWKSURL:  "https://login.microsoftonline.com/common/discovery/v2.0/keys",
    },
    IssuerValidator: oauth.AzureMultiTenantIssuer(), // any Azure v2.0 tenant
}
```

The `oauth.Microsoft` preset takes a tenant id and only works for one tenant,
so multi-tenant setups build the three endpoints by hand as above. Calling
`Discover` against the alias document (the `common` or `organizations`
discovery URL) does not work: the document publishes a `{tenantid}`
template issuer, and `Discover` requires the document's issuer to equal the
one you asked for byte-for-byte, so the alias document is refused at the
discovery step.

`AzureMultiTenantIssuer()` accepts any
`https://login.microsoftonline.com/<tenant>/v2.0` issuer. It trusts users
from **every** tenant: to restrict to specific tenants, also check the
`tid` claim via `IDClaims.Raw` against your allowlist. The predicate
replaces only the issuer check; signature, audience, expiry, `nonce` and
the signing key's `issuer` member, where Microsoft publishes one, with
the `{tenantid}` placeholder filled from the token's `tid` claim, are all
still enforced.

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
// Reject an empty saved state before the comparison: two empty byte
// slices compare equal under ConstantTimeCompare, so a callback that
// carries no "state" would otherwise pass when the cookie/session is
// missing, and Exchange would be called with an empty PKCE verifier.
gotState := r.FormValue("state")
if savedState == "" || subtle.ConstantTimeCompare([]byte(gotState), []byte(savedState)) != 1 {
    http.Error(w, "bad state", http.StatusBadRequest) // CSRF / stale
    return
}
tok, err := mod.Exchange(r.Context(), r.FormValue("code"), savedVerifier)
if err != nil { /* 401, Exchange returns nil on transport errors, non-2xx, and decode failures */ }

claims, err := mod.VerifyIDToken(r.Context(), tok.IDToken, savedNonce)
if err != nil { /* 401, never show the reason */ }

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
tok, err := mod.Exchange(r.Context(), code, savedVerifier)
if err != nil { /* 401, Exchange returns nil on transport errors, non-2xx, and decode failures */ }
info, err := mod.UserInfo(r.Context(), tok.AccessToken)
if err != nil { /* 401 */ }
// info is the provider's raw JSON: GitHub "id"/"login", Discord "id"/"username".
// Key your account on (provider, info["id"]).
```

`UserInfo` sends the access token as a Bearer credential, caps the response, and
returns the decoded JSON. There is no ID token to validate here — identity is
whatever the userinfo endpoint returns, so trust only the provider's stable id.

> Discord also publishes an OIDC discovery document. The `oauth.Discord()`
> preset uses this userinfo path on purpose, and it returns Discord's own user
> object from `users/@me`. To receive an ID token instead, build the provider
> with `Discover(ctx, "https://discord.com", nil)`; `Discover` parses Discord's
> published document, but an ID token from a live Discord login has not been run
> through `VerifyIDToken` here.

> Custom OAuth2 provider: set `Provider{AuthURL, TokenURL, UserInfoURL}` (no
> issuer/JWKS). A provider with neither issuer+JWKS nor a userinfo URL is
> rejected at `New` — it could not identify the user.

## Sign in with Apple

Apple publishes an OIDC discovery document, but its client secret is not a
shared string: it is a short-lived JWT signed with an ES256 key Apple gave
your team. The library exposes that signing step as `oauth.AppleClientSecret`,
returns a per-Exchange function from it, and wires it into `Config.ClientSecretFunc`.
The preset (`oauth.Apple()`) carries `response_mode=form_post` on the
authorization URL because the `name` scope requires it, so the callback
arrives as an HTTP POST: read `code` and `state` from the form the same
way you'd read them from a query string.

```go
secret, err := oauth.AppleClientSecret(teamID, keyID, servicesID, p8PEM)
if err != nil { /* startup error */ }
mod, err := oauth.New(auth, oauth.Config{
    ClientID:         servicesID,
    ClientSecretFunc: secret,
    RedirectURL:      "https://app.example.com/auth/apple/callback",
    Provider:         oauth.Apple(),
})
```

Two things the Apple integration has to get right:

- The first authorization only. Apple posts an unauthenticated `user` JSON
  blob on the first login. It holds the user's name (when the `name` scope
  was approved), may be used to prefill a display name, and has **no
  identity meaning**. Key accounts on the ID token's `sub` and treat
  `email` as a hint subject to the usual `email_verified` check.
- The `.p8` key. Apple delivers it once from the Developer portal; load it
  from a secret store or environment variable, never commit it. The library
  itself never logs the key or the signed client secret. Each Exchange
  signs a fresh five-minute secret (well under Apple's 15777000 s ceiling):
  a leaked secret is only good until its `exp`.

Apple accepts `client_secret_post` only; the secret is sent in the form
body, never in the `Authorization` header.

## What it guarantees

- **PKCE S256 always.** The `plain` method is never offered, so a downgrade
  cannot strip it. Works for public clients (no secret) too.
- **ID-token signature** is checked against the provider's JWKS, fetched and
  cached (1 h), refreshed automatically on an unknown `kid` so key rotation just
  works. Only asymmetric algorithms (RS/PS/ES) are accepted — `none` and HMAC
  are refused, closing the algorithm-confusion forgery.
- **Issuer, audience, `azp`, expiry, and nonce** are all enforced. A mismatch
  fails closed with `ErrIDTokenInvalid`.
- **A key's own issuer restriction.** Microsoft publishes an `issuer` on each
  key of its common JWKS, some pinned to one tenant and some holding the
  `{tenantid}` template. When the key that signed a token carries one, the
  token's `iss` must equal it, with the template completed from the token's
  `tid`, so a key scoped to one tenant cannot vouch for another.
- **Safe redirects.** The default HTTP client refuses redirects that are
  cross-origin (the token POST replays the client secret on a 307/308),
  downgrade to `http`, or target a loopback, link-local or private IP
  literal (SSRF; `isPrivateHost` only inspects IP literals, so a
  same-host https redirect to a hostname like `localhost` passes that
  check, and a same-host redirect is not refused by the cross-origin
  rule either, so a request that begins on `https://localhost` may be
  redirected to another path on `https://localhost`). The library's
  redirect policy always runs, on the default client and on any client
  you pass in: `Config.HTTPClient` is composed with that policy, not
  used in place of it. Your client's Transport, Timeout and Jar are
  preserved, and a `CheckRedirect` you provide is only invoked for
  redirects the library's redirect rule has already accepted. A client
  that allows cross-origin redirects still has them refused by the
  library before yours is consulted.

## What is yours

Sessions, cookies, CSRF on your own routes, and where you persist the per-request
secrets — same as the rest of authcore. See the
[secure login recipe](secure-login.md).
