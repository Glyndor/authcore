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

Each refresh token carries a random `rid` claim, so two tokens of one session
never compare equal, whatever the clock says. The `SessionID` (`jti`) is still
preserved across rotations; `rid` only guarantees the token bytes change.

The recommended pattern — verify the hash **before** calling `RotateTokens` to
prevent token-reuse attacks even if your database is compromised:

```go
// 1. Compute the hash of the token the client presented.
incoming, err := jwtMod.HashRefreshToken(clientToken)
if err != nil { return http.StatusInternalServerError }

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

// 5. Atomically replace the old hash in your database. The WHERE clause
//    pins the row to BOTH the session id and the hash you verified, so two
//    concurrent refreshes cannot both rotate: only the update that still
//    sees the old hash succeeds. Without that hash check, both requests
//    read the same hash, both pass `VerifyRefreshTokenHash`, and the last
//    write replaces the hash the other response already handed the client.
//    The row count is the control: a returned pair with rowsAffected == 0
//    means another request rotated first, and the new pair must not be
//    sent to the client.
res, err := db.Exec(`
    UPDATE sessions
       SET refresh_hash = $1
     WHERE id = $2
       AND refresh_hash = $3`,
    newPair.RefreshTokenHash, session.ID, incoming)
if err != nil {
    return http.StatusUnauthorized
}
rows, err := res.RowsAffected()
if err != nil || rows != 1 {
    return http.StatusUnauthorized // someone else rotated; discard newPair
}

// 6. Send the new tokens to the client.
```

### When not to rotate

Rotation is the recommended default, but there is one shape of client where it
actively hurts: a frontend that fires several requests in parallel. Two of them
find the access token expired at the same moment, both refresh with the same
refresh token, and the second arrives after step 5 has already replaced the
hash. It gets a 401 for a token that was valid when it was sent, and the user is
signed out mid-session for no reason. Next.js applications hit this often,
because the framework fans out data fetches on a single navigation.

Staying non-rotating is supported. Issue with `CreateTokens`, store the hash,
and verify with `VerifyRefreshTokenHash` on each refresh without ever calling
`RotateTokens`:

```go
// Refresh, without rotating: the client keeps the same refresh token.
if !jwtMod.VerifyRefreshTokenHash(clientToken, session.RefreshTokenHash) {
    return http.StatusUnauthorized
}
// VerifyRefreshTokenHash compares HMACs only. It does NOT check the
// token's signature, the token type, or the refresh expiry, so a
// refresh token that expired months ago still passes the comparison
// and lets you mint a fresh pair. Store the expiry alongside the hash
// at CreateTokens time and reject it here, before issuing anything.
if time.Now().After(session.RefreshTokenExpiresAt) {
    return http.StatusUnauthorized
}
// Mint a fresh pair, hand back only the access token, and keep the stored
// refresh hash as it is. Two requests racing here both succeed.
pair, err := jwtMod.CreateTokens(session.UserID, freshClaims)
if err != nil {
    return http.StatusUnauthorized
}
db.UpdateSessionID(session.ID, pair.SessionID) // see below: this is required
// Return pair.AccessToken. Do not send pair.RefreshToken.
```

Two things you give up, and the second one surprises people.

**You lose reuse detection.** Rotation is not what detects a stolen refresh
token; `RotateTokens` only verifies the presented token and reissues it. The
detection comes from step 5 above: once you have atomically replaced the stored
hash, a thief replaying the old token fails the lookup, and a legitimate client
failing the lookup tells you the token leaked. Drop rotation and you drop that
signal.

**The denylist stops killing the whole session at once.** `CreateTokens` mints a
fresh `jti` on every call, while `RotateTokens` carries the original one
forward. Measured on a fixed clock:

| Call | SessionID |
|---|---|
| `CreateTokens` | `018fd3ab-c200-771c-b0e0-17fa236d71af` |
| `CreateTokens` again | `018fd3ab-c200-7115-a937-fd114f66224d` |
| `RotateTokens` on the first pair | `018fd3ab-c200-771c-b0e0-17fa236d71af` |

So under rotation every access token in a session shares one `jti`, and a single
denylist entry kills all of them instantly, which is what the `Denylist`
documentation promises. Refresh with `CreateTokens` instead and each refresh
starts a new `jti`, so you must store the newest `SessionID` on the session row
and revoke that one. Access tokens minted under an earlier `jti` are not covered
by that entry and stay valid until their own `exp`, which is `AccessTokenTTL`,
15 minutes by default.

That is usually acceptable, but it is a different promise: instant for the
current segment, up to one access TTL for anything issued before it. If you need
the stronger guarantee, either rotate, or coalesce refreshes in the client so
only one is ever in flight.

So the trade is real in both directions:

- **Rotate** when your client refreshes from one place at a time, which covers
  most mobile apps and server-rendered sessions. You get reuse detection and a
  session-wide kill switch.
- **Do not rotate** when your client can refresh concurrently and you would
  rather not build request coalescing. Compensate with a shorter
  `AccessTokenTTL`, so the uncovered window shrinks, and keep the stored
  `SessionID` current.

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
hash, err := jwtMod.HashRefreshToken(clientToken)
if err != nil { return http.StatusInternalServerError }
db.DeleteSessionByHash(hash)
// The current access token still works for up to AccessTokenTTL. Plan for it.
```

What to do about it:

- **Good enough for most apps:** keep `AccessTokenTTL` short (the 15-minute
  default) so a logged-out token dies quickly on its own.
- **Need instant kill** (logout-everywhere, compromised account): set a
  `Denylist` on the config. `VerifyAccessToken` then checks it on every
  otherwise-valid access token, keyed by the `jti`/`SessionID` (stable across
  rotations), and returns `ErrTokenRevoked` for a killed session.

```go
// Your store — in-memory, Redis, a DB table. Must fail closed.
type myDenylist struct{ /* ... */ }
func (d *myDenylist) IsRevoked(ctx context.Context, jti string) (bool, error) {
    return d.store.Exists(ctx, "revoked:"+jti)
}

cfg := jwt.DefaultConfig()
cfg.Denylist = &myDenylist{ /* ... */ }
jwtMod, _ := jwt.New[MyClaims](auth, cfg)

// On logout / force-logout: add the session id to the store.
d.store.Add(ctx, "revoked:"+pair.SessionID, pair.RefreshTokenExpiresAt)

// Verification rejects it from then on:
claims, err := jwtMod.VerifyAccessTokenContext(ctx, token)
if errors.Is(err, jwt.ErrTokenRevoked) { /* 401, re-authenticate */ }
```

The denylist is opt-in: leave `Denylist` nil and verification stays fully
stateless (no per-request lookup). The lookup runs only for tokens that already
passed signature and expiry, so a garbage token never touches your store. Use
`VerifyAccessTokenContext` to pass a request context to the lookup; a store
error fails closed (the token is rejected). Size the store entries to expire at
the access token's `exp` **plus** `ClockSkewLeeway`: verification accepts a
token up to `exp + leeway`, so an entry that disappears at `exp` leaves a
window of `leeway` in which a revoked token still validates.

## Clock skew tolerance

In distributed systems, server clocks may drift by a few seconds. Set
`ClockSkewLeeway` to accept tokens that expired within that window:

```go
cfg.ClockSkewLeeway = 30 * time.Second
```

The leeway applies to both access and refresh token verification. Keep it small
— large values reduce the security margin of short-lived tokens.
