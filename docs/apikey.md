# API keys

`auth/apikey` issues and verifies opaque API keys — for authenticating machines
(a CLI, a service, a webhook caller) where a password or a short-lived JWT does
not fit. The library never stores anything; you store a hash. See the
[error reference](errors.md).

## Setup

```go
auth, err := authcore.New(authcore.DefaultConfig())
keyMod, err := apikey.New(auth) // default prefix "ak"
```

## Key shape

```
ak_<id>_<secret>
```

- **prefix** — a short fixed tag (default `ak`) so a leaked key is recognisable
  in logs and secret scanners. Override with `apikey.Config{Prefix: "svc"}` —
  1–16 lowercase letters/digits.
- **id** — a random public identifier. Store it in plaintext and use it as the
  database lookup key, so verification is an O(1) row fetch, not a scan.
- **secret** — 256 bits of CSPRNG output. Only its keyed hash is stored.

## Issuing

```go
key, err := keyMod.Generate()
// Show key.Key to the user ONCE — it is never recoverable.
// Store key.ID (lookup) and key.Hash. Never store key.Key.
db.StoreAPIKey(key.ID, key.Hash, userID)
```

## Verifying

```go
id, err := keyMod.ParseID(presented)
if err != nil { return http.StatusUnauthorized } // malformed

row, err := db.FindAPIKey(id)
if err != nil || !keyMod.Verify(presented, row.Hash) {
    return http.StatusUnauthorized
}
// authenticated as row.UserID
```

`Verify` compares in **constant time** (`crypto/subtle`).

> **Why not Argon2id?** An API key is 256 bits of random — brute-forcing it is
> infeasible regardless of hash speed, and a per-request call must not pay
> Argon2id's cost. Keys are hashed with **keyed HMAC-SHA256**, peppered with the
> library's managed secret, so a leaked database of hashes is useless without
> the server secret too. (Passwords are different — they are low-entropy and use
> Argon2id; see [Password hashing](password.md).)

## Revoking

Delete the row (or flag it) and check on lookup. There is no token to expire —
an API key lives until you remove it, so build rotation/expiry into your own
schema if you need it.
