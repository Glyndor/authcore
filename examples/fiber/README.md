# examples/fiber — full auth API with Fiber v3

A runnable HTTP server that wires AuthCore into [Fiber v3](https://gofiber.io). Register, login, access a protected route, rotate tokens.

> This example is its own Go module (separate `go.mod`) so the root library has no runtime dependency on Fiber. Run it from this directory.

## Run

```bash
cd examples/fiber
go run .
```

Server listens on `:3000`.

## Routes

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `POST` | `/register` | — | Hash + store the new user's password |
| `POST` | `/login` | — | Verify password, issue an access + refresh pair |
| `GET` | `/me` | `Authorization: Bearer <access>` | Verify the access token, return claims |
| `POST` | `/refresh` | refresh token in body | Rotate the pair, replace the stored hash |

## Try it

```bash
# 1. Register
curl -X POST localhost:3000/register \
  -H 'content-type: application/json' \
  -d '{"email":"ana@example.com","password":"Str0ng-P@ssword!"}'

# 2. Login — capture the tokens
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
- `jwtMod.VerifyAccessToken` in a Fiber middleware for `/me`.
- `jwtMod.HashRefreshToken` → DB lookup → `jwtMod.VerifyRefreshTokenHash` → `jwtMod.RotateTokens` — the full anti-reuse rotation pattern.

User storage is an in-memory `map` for brevity — swap it for your real database.
