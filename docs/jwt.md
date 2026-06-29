# JWT authentication

`auth/jwt` signs and verifies access + refresh tokens with EdDSA (Ed25519),
supports generic custom claims, and handles rotation — all timing-safe. See the
[error reference](errors.md) for every sentinel error and the
[runnable example](../examples/jwt/).

## Setup

```go
cfg := jwt.DefaultConfig()
cfg.Issuer   = "https://auth.example.com"
cfg.Audience = []string{"https://api.example.com"}

// Optional: tolerate up to 30 s of clock drift between servers.
cfg.ClockSkewLeeway = 30 * time.Second

jwtMod, err := jwt.New[UserClaims](auth, cfg)
```

`jwt.DefaultConfig()` values:

| Field | Default | Max |
|---|---|---|
| `AccessTokenTTL` | 15 minutes | 24 hours |
| `RefreshTokenTTL` | 24 hours | 365 days |
| `Issuer` | `"github.com/Glyndor/authcore"` | — |
| `Audience` | `["github.com/Glyndor/authcore"]` | — |
| `ClockSkewLeeway` | 0 (no leeway) | — |

> [!NOTE]
> `validateConfig` rejects TTLs above the ceilings listed above. This prevents
> issuing effectively permanent bearer tokens by accident (e.g. typing
> `10 * time.Hour` where `10 * time.Minute` was intended).

## Login — creating a token pair

```go
// subject must be a UUID v7 (RFC 9562 §5.7).
pair, err := jwtMod.CreateTokens(userID, UserClaims{Name: "Ana", Role: "admin"})
if err != nil {
    // jwt.ErrInvalidSubject — subject is not a valid UUID v7
}

pair.AccessToken            // short-lived JWT for API requests
pair.AccessTokenExpiresAt   // time.Time — tell the client when to refresh
pair.RefreshToken           // long-lived JWT for token rotation
pair.RefreshTokenExpiresAt  // time.Time — when the user must log in again
pair.RefreshTokenHash       // HMAC-SHA256 hex digest — store this in your DB
pair.SessionID              // UUID v7 jti shared by both tokens — use as session PK
```

> **Never store the raw refresh token.** Store only `RefreshTokenHash`.

## Authenticating requests

```go
claims, err := jwtMod.VerifyAccessToken(tokenFromHeader)
switch {
case errors.Is(err, jwt.ErrTokenExpired):
    // 401 — client should refresh
case errors.Is(err, jwt.ErrTokenInvalid):
    // 401 — tampered, wrong key, or issuer/audience mismatch
case errors.Is(err, jwt.ErrTokenMalformed):
    // 400 — not a JWT at all
case err != nil:
    // 401 — catch-all
}

fmt.Println(claims.Subject)    // UUID v7 user ID
fmt.Println(claims.Extra.Role) // "admin" — your custom claims
fmt.Println(claims.ExpiresAt)  // time.Time
```

> [!NOTE]
> Verification enforces both **`iss` (issuer)** and **`aud` (audience)** match
> the values in `jwt.Config`. A token signed by a trusted key but minted for a
> different service is rejected with `ErrTokenInvalid` — this is the defense
> against accidental key reuse across services.

## Rotating tokens

The recommended pattern — verify the hash **before** calling `RotateTokens` to
prevent token-reuse attacks even if your database is compromised:

```go
// 1. Compute the hash of the token the client presented.
incoming := jwtMod.HashRefreshToken(clientToken)

// 2. Look it up in your database.
session, err := db.FindSessionByHash(incoming)
if err != nil {
    return http.StatusUnauthorized
}

// 3. Use timing-safe comparison to verify the hash matches.
//    This prevents timing attacks on the lookup result.
if !jwtMod.VerifyRefreshTokenHash(clientToken, session.RefreshTokenHash) {
    return http.StatusUnauthorized
}

// 4. Rotate — authcore verifies the token's signature and expiry.
freshClaims := UserClaims{Name: session.UserName, Role: session.UserRole}
newPair, err := jwtMod.RotateTokens(clientToken, freshClaims)
if err != nil {
    return http.StatusUnauthorized
}

// 5. Atomically replace the old hash in your database.
db.ReplaceRefreshHash(session.ID, newPair.RefreshTokenHash)

// 6. Send the new tokens to the client.
```

## Revocation & logout

Access tokens are **stateless JWTs**: once issued, an access token stays valid
until its `exp` (the `AccessTokenTTL`, 15 minutes by default). The library holds
no session store, so there is no way to invalidate an individual access token
before it expires.

This matters for logout. Deleting the stored refresh-token hash on logout stops
the session from being **renewed**, but it does **not** kill the access token
the client already holds — that token keeps working until it expires.

```go
// Logout: delete the refresh hash so the session cannot be renewed.
db.DeleteSessionByHash(jwtMod.HashRefreshToken(clientToken))
// The current access token still works for up to AccessTokenTTL. Plan for it.
```

What to do about it:

- **Good enough for most apps:** keep `AccessTokenTTL` short (the 15-minute
  default) so a logged-out token dies quickly on its own.
- **Need instant kill** (logout-everywhere, compromised account): maintain your
  own denylist keyed by the `SessionID`/`jti` (it is stable across rotations)
  and check it in your middleware after `VerifyAccessToken`, or shorten
  `AccessTokenTTL` further.

## Clock skew tolerance

In distributed systems, server clocks may drift by a few seconds. Set
`ClockSkewLeeway` to accept tokens that expired within that window:

```go
cfg.ClockSkewLeeway = 30 * time.Second
```

The leeway applies to both access and refresh token verification. Keep it small
— large values reduce the security margin of short-lived tokens.
