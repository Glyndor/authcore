# Error handling

Always use `errors.Is` for error inspection. Errors may be wrapped:

```go
claims, err := jwtMod.VerifyAccessToken(token)
if errors.Is(err, jwt.ErrTokenExpired) {
    // prompt the client to refresh
}
```

## `authcore` package

| Error | Client-safe? | When |
|---|---|---|
| `authcore.ErrInvalidConfig` | ✗ No | `Config` validation failed |
| `authcore.ErrInvalidTimezone` | ✗ No | `Config.Timezone` is nil. Unreachable from `authcore.New`: `New` replaces a nil `Timezone` with `time.UTC` before validation. Reserved for direct calls to the unexported validator. |
| `authcore.ErrKeyManager` | ✗ No | key generation or loading failed, or a `Config.KeyStore` returned no material or material of the wrong shape (see [Key management](../guides/key-management.md#what-a-custom-load-must-return)) |

## `auth/jwt` package

| Error | Client-safe? | When |
|---|---|---|
| `jwt.ErrInvalidConfig` | ✗ No | `jwt.Config` validation failed |
| `jwt.ErrTokenExpired` | ✓ Yes | `exp` claim is in the past (beyond leeway) |
| `jwt.ErrTokenInvalid` | ✗ No | signature invalid, unsupported algorithm, `iss` / `aud` claim does not match `Config`, `iat` or `nbf` in the future beyond the leeway, a missing or invalid `sub` or `jti`, a missing required claim, or a `crit` header |
| `jwt.ErrTokenMalformed` | ✗ No | not a valid three-part JWT string |
| `jwt.ErrWrongTokenType` | ✗ No | access token passed where refresh expected, or vice-versa |
| `jwt.ErrInvalidSubject` | ✗ No | subject passed to `CreateTokens` is not a UUID v7 |
| `jwt.ErrTokenRevoked` | ✗ No | a configured `Denylist` reports the token's session revoked; also returned by `RotateTokens`. A failure of the store is not this error: it arrives as `jwt: denylist lookup: ...` and the token is refused (fail closed) |
| `jwt.ErrTokenOversized` | ✗ No | a token to verify is over 8 KiB, or the pair to issue would be |
| `jwt.ErrNotInitialised` | ✗ No | method called on a `JWT` that `New` did not build (a zero value) |

## `auth/password` package

| Error | Client-safe? | When |
|---|---|---|
| `password.ErrInvalidConfig` | ✗ No | `password.Config` validation failed |
| `password.ErrInvalidHash` | ✗ No | stored hash is malformed or not Argon2id PHC format |
| `password.ErrWeakPassword` | ✓ Yes | plaintext does not meet the built-in policy |
| `password.ErrNonPrintableCharacter` | ✓ Yes | the reason inside `ErrWeakPassword` when the NFC-normalized plaintext passes the length checks but holds a control, invisible or otherwise non-printable character, or invalid UTF-8 |

## `auth/email` package

| Error | Client-safe? | When |
|---|---|---|
| `email.ErrInvalidEmail` | ✓ Yes | Address fails RFC 5321/5322 validation, or `Config.RejectPlusAddressing` is set and the local part contains `+`; `errors.Unwrap` gives the specific rule |
| `email.ErrDomainNoMX` | ✓ Yes | Domain has no MX records or does not exist (the resolver answered NXDOMAIN or NODATA); it cannot receive email |
| `email.ErrDomainUnresolvable` | ✗ No | DNS lookup failed; treat as soft failure, do not block the user |
| `email.ErrInvalidConfig` | ✗ No | `New`/`NewWithConfig` was given a nil provider or a provider with no logger |

## `auth/username` package

| Error | Client-safe? | When |
|---|---|---|
| `username.ErrInvalidUsername` | ✓ Yes | Username fails a validation rule; `errors.Unwrap` gives the specific rule |
| `username.ErrInvalidConfig` | ✗ No | `username.Config` validation failed (startup error, treat as 500) |

## `auth/apikey` package

| Error | Client-safe? | When |
|---|---|---|
| `apikey.ErrInvalidConfig` | ✗ No | `apikey.Config` validation failed (e.g. malformed prefix): startup error |
| `apikey.ErrInvalidKey` | ✗ No | Presented key is malformed (`ParseID`); return a generic unauthorized |
| `apikey.ErrNotInitialised` | ✗ No | `Generate`/`Hash` called on a zero-value `APIKey` (a module that was never constructed by `New`) |

## `auth/credential` package

| Error | Client-safe? | When |
|---|---|---|
| `credential.ErrInvalidConfig` | ✗ No | `credential.Config` validation failed (zero/negative/oversized TTL, multiple Configs, nil provider, wrong refresh-secret length): startup error |
| `credential.ErrInvalidCredential` | ✓ Yes | `Verify`: the presented token does not match the stored hash under the given purpose and subject: return a generic "link invalid or expired" |
| `credential.ErrExpired` | ✓ Yes | `Verify`: the token matched the stored hash but `issuedAt` is more than `TTL` in the past, or more than one minute in the future: return the same generic message as `ErrInvalidCredential` |
| `credential.ErrEmptyPurpose` | ✗ No | `Issue` called with an empty `purpose`; the hash would be unbound and redeemable against any flow |
| `credential.ErrEmptySubject` | ✗ No | `Issue` called with an empty `subject`; the token would not be attributable to any user |
| `credential.ErrNotInitialised` | ✗ No | `Issue`/`Verify` called on a zero-value `Credential` (a module that was never constructed by `New`) |

## `auth/field` package

| Error | Client-safe? | When |
|---|---|---|
| `field.ErrInvalidConfig` | ✗ No | `field.Config` validation failed (today: an empty `Context`), or `New` was given a nil provider or a `Keys().RefreshSecret()` of the wrong length: startup error |
| `field.ErrDecrypt` | ✓ Yes | The message is safe to show, but the failure is a server-side data problem: return a generic 500, never a 404, and log the row id. `Decrypt` failed for any reason: input shorter than the nonce plus GCM tag, input not valid base64, or GCM authentication tag mismatch. The three are not distinguished, so treat the row as corrupt or from the wrong column |
| `field.ErrNotInitialised` | ✗ No | `Encrypt`/`Decrypt`/`BlindIndex` called on a zero-value `Field` (a module that was never constructed by `New`) |

## `auth/oauth` package

| Error | Client-safe? | When |
|---|---|---|
| `oauth.ErrInvalidConfig` | ✗ No | `oauth.Config` validation failed (missing/non-https endpoints, no identity source) |
| `oauth.ErrExchange` | ✗ No | Authorization-code exchange failed (transport, non-2xx, or OAuth error) |
| `oauth.ErrNoIDToken` | ✗ No | OIDC provider returned no `id_token` |
| `oauth.ErrIDTokenInvalid` | ✗ No | ID token failed validation (signature, alg, `iss`/`aud`/`exp`/`nonce`/`azp`, or an `iss` outside the signing key's `issuer`); return generic unauthorized |
| `oauth.ErrJWKS` | ✗ No | Provider signing keys could not be fetched or parsed |
| `oauth.ErrJWKSStale` | ✗ No | The cached key set is past its TTL and could not be refreshed: the refresh failed, or the previous refresh failed less than the retry interval ago. It wraps `ErrJWKS`, so `errors.Is(err, oauth.ErrJWKS)` also matches |
| `oauth.ErrUserInfo` | ✗ No | Userinfo call failed (transport, non-2xx, undecodable) |
| `oauth.ErrNoUserInfo` | ✗ No | `UserInfo` called on a provider with no userinfo URL: programming error |
| `oauth.ErrDiscovery` | ✗ No | OIDC discovery failed (fetch/parse, or issuer mismatch) |

## `auth/totp` package

| Error | Client-safe? | When |
|---|---|---|
| `totp.ErrInvalidConfig` | ✗ No | `totp.Config` validation failed at startup (treat as 500), or `Enroll` was given an empty or whitespace-only account name (validate the name before calling: a user-supplied empty name is a 400) |
| `totp.ErrInvalidSecret` | ✗ No | Stored secret is not base32 or not 20 bytes decoded (storage corruption) |
| `totp.ErrMalformedCode` | ✓ Yes | Presented code is not six decimal digits |
| `totp.ErrNotInitialised` | ✗ No | Method called on a `TOTP` that `New` did not build (a zero value) |
| `totp.ErrInvalidCode` | ✓ Yes | Presented code does not match any step in the window |
| `totp.ErrCodeReused` | ✓ Yes | Recorder refused to advance the stored step; the code (or its step) was already accepted |
| `totp.ErrStepRecorderRequired` | ✗ No | `Verify` was called with a nil `StepRecorder` (programming error, treat as 500) |
