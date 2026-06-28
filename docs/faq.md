# FAQ

## Do I need a database to use authcore?

No — authcore never touches your database. It hashes passwords, signs tokens,
and validates input. *You* store hashes, usernames, and refresh-token hashes
wherever your app already keeps data (Postgres, Redis, SQLite, even an in-memory
`map` for a toy project).

## What is a UUID v7 and why does `CreateTokens` require one?

UUID v7 is a 128-bit identifier whose first 48 bits are a millisecond Unix
timestamp (RFC 9562 §5.7). That means UUID v7 values **sort naturally by
creation time** — ideal as a database primary key and as a stable session
identifier. authcore requires v7 for the `sub` claim so your sessions always sort
chronologically.

Libraries that generate UUID v7 in Go: `github.com/google/uuid` (≥ v1.6),
`github.com/gofrs/uuid`.

## Do I really need refresh token rotation?

Short answer: yes, if your refresh token lives longer than a few minutes.
Rotation limits the blast radius of a stolen refresh token — once the legitimate
client rotates, the stolen copy is rejected. Combined with storing only the
**hash** of refresh tokens on the server, an attacker who dumps your database
still cannot forge new sessions.

## My access token fails verification in a distributed system — is clock skew the issue?

Yes. Different servers may have clocks that drift a few seconds apart, causing
`ErrTokenExpired` on a brand-new token. Set `ClockSkewLeeway` in your JWT config:

```go
cfg := jwt.DefaultConfig()
cfg.ClockSkewLeeway = 5 * time.Second
```

Keep it small (5–30 s). Larger values erode the security margin of short-lived
tokens.

## I'm getting `ErrKeyManager` on startup. What went wrong?

authcore could not read or create its key files. Check that:

1. `KeysDir` (default `.authcore`) is writable by the process.
2. The directory is not a read-only filesystem (common in some container setups).
3. Existing key files are not corrupted — delete `.authcore` and let authcore
   regenerate them. **Warning:** regenerating keys invalidates every token
   currently in circulation.

## Can I verify tokens issued before I rotated my signing key?

Yes. authcore embeds the `kid` (key ID) in every token header. When you add a new
key pair, keep the old public key in the key store under its original `kid`. The
verifier will select the right key automatically. See
[Key management](key-management.md) for the rotation workflow.

## My existing password hashes were created with a different library. Can I migrate?

Yes. See [Migrating](migrating.md) for the re-hash-on-next-login pattern. If your
hashes are already in PHC Argon2id format (`$argon2id$v=19$…`), no migration is
needed at all — `pwdMod.Verify` reads parameters from the stored hash.

## Can I run authcore in Docker / Kubernetes?

Yes. Point `KeysDir` at a mounted secrets volume so keys survive container
restarts and are shared across replicas:

```go
cfg := authcore.DefaultConfig()
cfg.KeysDir = os.Getenv("AUTHCORE_KEYS_DIR") // e.g. /run/secrets/authcore
```

Pre-generate the key files once (a one-shot job that runs authcore against the
volume), then mount them read-only into your app.

## The `Hash` call is slower than expected in tests. Is that normal?

Yes — Argon2id deliberately takes ~100–300 ms and allocates 64 MiB of RAM per
call. In tests, use a low-cost config to avoid slow suites:

```go
pwd, _ := password.New(auth, password.Config{
    Memory:      8 * 1024, // minimum allowed (8 MiB)
    Iterations:  1,
    Parallelism: 1,
})
```

## Does authcore ship an HTTP server, middleware, or CSRF protection?

No — authcore gives you the primitives (hash, sign, verify, rotate) and stays
framework-agnostic. See [`examples/fiber`](../examples/fiber/) and
[`examples/gin`](../examples/gin/) for wiring into a real HTTP stack, including
protected-route middleware.
