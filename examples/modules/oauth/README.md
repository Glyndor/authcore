# auth/oauth: social login example

A runnable two-route OIDC / OAuth2 login flow. Point it at a live provider to
smoke-test the whole handshake end to end.

## Run

```bash
cd examples/modules/oauth
OAUTH_PROVIDER=google \
OAUTH_CLIENT_ID=your-client-id \
OAUTH_CLIENT_SECRET=your-client-secret \
go run .
```

Then open <http://localhost:8080/login>. After you approve at the provider, the
callback prints the resolved identity as JSON.

Register `http://localhost:8080/callback` as the redirect URI with your provider
(or set `OAUTH_REDIRECT_URL`).

## Providers

| `OAUTH_PROVIDER` | Kind | Identity from |
|---|---|---|
| `google` (default) | OIDC | `VerifyIDToken` |
| `microsoft` | OIDC | `VerifyIDToken` (set `OAUTH_TENANT` to a specific tenant id; the `common`/`organizations` aliases fail exact-issuer validation) |
| `apple` | OIDC | `VerifyIDToken` (needs `APPLE_TEAM_ID`, `APPLE_KEY_ID` and `APPLE_PRIVATE_KEY_FILE`; `OAUTH_CLIENT_SECRET` must be unset, the secret is signed from the `.p8` key) |
| `vercel` | OIDC | `VerifyIDToken` |
| `github` | OAuth2 | `UserInfo` |
| `discord` | OAuth2 | `UserInfo` |

## What it shows

| Step | API |
|---|---|
| Start: build redirect with PKCE + state + nonce | `mod.AuthCodeURL()` |
| Callback: verify state, swap the code | `mod.Exchange(ctx, code, verifier)` |
| OIDC: validate the ID token | `mod.VerifyIDToken(ctx, idToken, nonce)` |
| OAuth2: fetch the profile | `mod.UserInfo(ctx, accessToken)` |

> The example keeps `state`/`nonce`/`verifier` in a plain `HttpOnly` cookie for
> brevity. In production sign that cookie (and set `Secure`) or use a
> server-side session, and serve over HTTPS. See the
> [secure login recipe](../../../docs/guides/secure-login.md).

## What the callback checks

- `/login` and `/callback` answer only `GET` (and `POST` on `/callback` for a `form_post` provider such as Apple); every other method is a 405.
- The redirect target, the client id and the redirect URI come from the library and the configuration, never from a request parameter.
- The flow cookie is scoped to `/callback`, is spent on the first callback whatever its outcome, and a callback with an empty `state`, an empty verifier, or a repeated `state`/`code` parameter is refused before the code is exchanged.
- For OIDC providers the nonce stored in the cookie must be the one inside the ID token.
- A provider's `error` and `error_description`, and the text of a failed exchange, are never echoed to the page or written to the log.
- Responses are `Cache-Control: no-store`, the server sets every timeout, and a form POST is capped at 16 KiB.

The cookie is still a demo shortcut: it is neither signed nor bound to a server-side session, so whoever can plant a cookie for this host can choose the flow's state. Sign it, or keep the state on the server, before you copy this.
