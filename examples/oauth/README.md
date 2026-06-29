# auth/oauth — social login example

A runnable two-route OIDC / OAuth2 login flow. Point it at a live provider to
smoke-test the whole handshake end to end.

## Run

```bash
OAUTH_PROVIDER=google \
OAUTH_CLIENT_ID=your-client-id \
OAUTH_CLIENT_SECRET=your-client-secret \
go run ./examples/oauth
```

Then open <http://localhost:8080/login>. After you approve at the provider, the
callback prints the resolved identity as JSON.

Register `http://localhost:8080/callback` as the redirect URI with your provider
(or set `OAUTH_REDIRECT_URL`).

## Providers

| `OAUTH_PROVIDER` | Kind | Identity from |
|---|---|---|
| `google` (default) | OIDC | `VerifyIDToken` |
| `microsoft` | OIDC | `VerifyIDToken` (set `OAUTH_TENANT` to a specific tenant id — the `common`/`organizations` aliases fail exact-issuer validation) |
| `github` | OAuth2 | `UserInfo` |
| `discord` | OAuth2 | `UserInfo` |

## What it shows

| Step | API |
|---|---|
| Start — build redirect with PKCE + state + nonce | `mod.AuthCodeURL()` |
| Callback — verify state, swap the code | `mod.Exchange(ctx, code, verifier)` |
| OIDC — validate the ID token | `mod.VerifyIDToken(ctx, idToken, nonce)` |
| OAuth2 — fetch the profile | `mod.UserInfo(ctx, accessToken)` |

> The example keeps `state`/`nonce`/`verifier` in a plain `HttpOnly` cookie for
> brevity. In production sign that cookie (and set `Secure`) or use a
> server-side session, and serve over HTTPS — see the
> [secure login recipe](../../docs/secure-login.md).
