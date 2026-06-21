# auth/jwt — access + refresh token example

End-to-end JWT flow: create a pair, verify the access token, handle errors, rotate on refresh.

## Run

```bash
go run ./examples/jwt
```

## What it shows

| Step | API |
|---|---|
| Login — issue a token pair | `jwtMod.CreateTokens(subject, extra)` |
| Authenticated request — verify the access token | `jwtMod.VerifyAccessToken(token)` |
| Error handling — `ErrTokenExpired`, `ErrTokenMalformed`, `ErrWrongTokenType` | `errors.Is` |
| Token rotation — exchange a refresh token for a new pair | `jwtMod.RotateTokens(refreshToken, freshClaims)` |

`SessionID` (a UUID v7 `jti`) stays stable across rotations — use it as the primary key of your session row.

## Expected output (abridged)

```
=== Login — CreateTokens ===
access token  : eyJhbGciOiJFZERTQSIsImtpZCI6Ij…
access exp    : 2026-XX-XX XX:XX:XX +0000 UTC
refresh exp   : 2026-XX-XX XX:XX:XX +0000 UTC
session ID    : 019da3ab-cc0b-795f-8cf3-30e87a9acbe8
refresh hash  : dedfb1afef8ee0f7  ← store this in DB

=== Authenticated request — VerifyAccessToken ===
subject  : 019600ab-1234-7000-8000-000000000001
name     : Ana García
role     : admin
token id : 019da3ab-cc0b-795f-8cf3-30e87a9acbe8

=== Error handling ===
ErrTokenMalformed caught correctly

=== Token rotation — RotateTokens ===
new access token : eyJhbGciOiJFZERTQSIsImtpZCI6Ij…
new refresh hash : dedfb1afef8ee0f7  ← replace old hash in DB
```

## Next

For a full HTTP server wiring, see [`examples/fiber`](../fiber/) or [`examples/gin`](../gin/).
