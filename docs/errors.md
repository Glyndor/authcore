# Error handling

Always use `errors.Is` for error inspection — errors may be wrapped:

```go
claims, err := jwtMod.VerifyAccessToken(token)
if errors.Is(err, jwt.ErrTokenExpired) {
    // prompt the client to refresh
}
```

## `authcore` package

| Error | When |
|---|---|
| `authcore.ErrInvalidConfig` | `Config` validation failed |
| `authcore.ErrInvalidTimezone` | `Config.Timezone` is nil |
| `authcore.ErrKeyManager` | key generation or loading failed |

## `auth/jwt` package

| Error | When |
|---|---|
| `jwt.ErrInvalidConfig` | `jwt.Config` validation failed |
| `jwt.ErrTokenExpired` | `exp` claim is in the past (beyond leeway) |
| `jwt.ErrTokenInvalid` | signature invalid, unsupported algorithm, or `iss` / `aud` claim does not match `Config` |
| `jwt.ErrTokenMalformed` | not a valid three-part JWT string |
| `jwt.ErrWrongTokenType` | access token passed where refresh expected, or vice-versa |
| `jwt.ErrInvalidSubject` | subject passed to `CreateTokens` is not a UUID v7 |
| `jwt.ErrTokenRevoked` | a configured `Denylist` reports the token's session revoked |

## `auth/password` package

| Error | When |
|---|---|
| `password.ErrInvalidConfig` | `password.Config` validation failed |
| `password.ErrInvalidHash` | stored hash is malformed or not Argon2id PHC format |
| `password.ErrWeakPassword` | plaintext does not meet the built-in policy |

## `auth/email` package

| Error | Client-safe? | When |
|---|---|---|
| `email.ErrInvalidEmail` | ✓ Yes | Address fails RFC 5321/5322 validation; `errors.Unwrap` gives the specific rule |
| `email.ErrDomainNoMX` | ✓ Yes | Domain exists but has no MX records (cannot receive email) |
| `email.ErrDomainUnresolvable` | ✗ No | DNS lookup failed; treat as soft failure, do not block the user |

## `auth/username` package

| Error | Client-safe? | When |
|---|---|---|
| `username.ErrInvalidUsername` | ✓ Yes | Username fails a validation rule; `errors.Unwrap` gives the specific rule |

## `auth/apikey` package

| Error | Client-safe? | When |
|---|---|---|
| `apikey.ErrInvalidConfig` | ✗ No | `apikey.Config` validation failed (e.g. malformed prefix) — startup error |
| `apikey.ErrInvalidKey` | ✗ No | Presented key is malformed (`ParseID`); return a generic unauthorized |

## `auth/oauth` package

| Error | Client-safe? | When |
|---|---|---|
| `oauth.ErrInvalidConfig` | ✗ No | `oauth.Config` validation failed (missing/non-https endpoints, no identity source) |
| `oauth.ErrExchange` | ✗ No | Authorization-code exchange failed (transport, non-2xx, or OAuth error) |
| `oauth.ErrNoIDToken` | ✗ No | OIDC provider returned no `id_token` |
| `oauth.ErrIDTokenInvalid` | ✗ No | ID token failed validation (signature, alg, `iss`/`aud`/`exp`/`nonce`/`azp`) — return generic unauthorized |
| `oauth.ErrJWKS` | ✗ No | Provider signing keys could not be fetched or parsed |
| `oauth.ErrUserInfo` | ✗ No | Userinfo request failed (transport, non-2xx, undecodable) |
| `oauth.ErrNoUserInfo` | ✗ No | `UserInfo` called on a provider with no userinfo URL — programming error |
| `oauth.ErrDiscovery` | ✗ No | OIDC discovery failed (fetch/parse, or issuer mismatch) |
| `username.ErrInvalidConfig` | ✗ No | `username.Config` validation failed (startup error, treat as 500) |
