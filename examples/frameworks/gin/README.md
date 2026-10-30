# examples/frameworks/gin: full auth API with Gin

A runnable HTTP server that wires AuthCore into [Gin](https://gin-gonic.com). Same routes as the Fiber example, different framework.

> This example is its own Go module (separate `go.mod`) so the root library has no runtime dependency on Gin. Run it from this directory.

## Run

```bash
cd examples/frameworks/gin
go run .
```

Server listens on `:3000`.

## Routes

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `POST` | `/register` | none | Hash + store the new user's password |
| `POST` | `/login` | none | Verify password, issue an access + refresh pair |
| `GET` | `/me` | `Authorization: Bearer <access>` | Verify the access token, return claims |
| `POST` | `/refresh` | refresh token in body | Rotate the pair, replace the stored hash |

## Try it

```bash
# 1. Register
curl -X POST localhost:3000/register \
  -H 'content-type: application/json' \
  -d '{"email":"ana@example.com","password":"Str0ng-P@ssword!"}'

# 2. Login: capture the tokens
curl -X POST localhost:3000/login \
  -H 'content-type: application/json' \
  -d '{"email":"ana@example.com","password":"Str0ng-P@ssword!"}'

# 3. Protected route
curl localhost:3000/me -H 'authorization: Bearer <access-token>'

# 4. Rotate
curl -X POST localhost:3000/refresh \
  -H 'content-type: application/json' \
  -d '{"refresh_token":"<refresh-token>"}'
```

## What it shows

- `Provider` passed to multiple modules once at startup.
- `pwdMod.Hash` / `pwdMod.Verify` for registration + login.
- `jwtMod.CreateTokens` with typed `UserClaims`.
- `jwtMod.VerifyAccessToken` in a Gin middleware for `/me`.
- `jwtMod.HashRefreshToken` → DB lookup → `jwtMod.VerifyRefreshTokenHash` → `jwtMod.RotateTokens`: single-use refresh tokens: a token that was already rotated is refused with 401. The example does not detect reuse or revoke the session; `docs/guides/secure-login.md` section 5 describes what a service that needs that adds.

## Before you copy this

The example covers the token flow, not the whole perimeter. What it does and what it leaves to you:

- **Input is bounded.** Bodies are capped at 16 KiB, the server sets every timeout, the address is normalized and validated, and a login password longer than 1 KiB is refused before it is hashed.
- **Login does not reveal which accounts exist.** An unknown address is verified against a decoy hash, so it costs one Argon2id derivation and answers byte for byte like a wrong password.
- **Registration does reveal it.** A taken address answers `409`, which lets a caller enumerate accounts. Accept that in a demo only; in production answer every registration the same way and send the outcome to the mailbox.
- **No rate limit.** Nothing slows repeated attempts per address or per client, so online password guessing is only bounded by the cost of Argon2id. That cost is memory as well as time: the example lets at most four derivations run at once (`maxConcurrentHashes`) and answers 503 with `Retry-After` to a request that waits more than two seconds for a slot, because 64 concurrent logins with the default profile measured 3.1 GiB. Put a limiter in front (per address and per IP) and lock or delay after repeated failures.
- **No logout and no revocation list.** Rotating or discarding the refresh token ends the session, but an access token that was already issued stays valid until it expires. Keep access tokens short, and add a revocation check on `/me` if you need an immediate cut-off.
- **Tokens travel in JSON bodies and the `Authorization` header.** There are no cookies, so there is no CSRF surface here; if you move the refresh token to a cookie, make it `HttpOnly`, `Secure` and `SameSite` and add CSRF protection.
- **One session per account.** A new login replaces the stored refresh hash.
- **User storage is an in-memory `map`** for brevity, so accounts vanish on restart. Swap it for your real database and keep the unique constraint on the address.
