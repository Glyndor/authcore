# API keys

`auth/apikey` issues and verifies opaque API keys for authenticating machines
(a CLI, a service, a webhook caller) where a password or a short-lived JWT does
not fit. The library never stores anything; you store a hash. See the
[error reference](../reference/errors.md).

## Setup

```go
auth, err := authcore.New(authcore.DefaultConfig())
keyMod, err := apikey.New(auth) // default prefix "ak"
```

## Key shape

```
ak_<id>_<secret>
```

- **prefix**: a short fixed tag (default `ak`) so a leaked key is recognisable
  in logs and secret scanners. Override with `apikey.Config{Prefix: "svc"}`:
  1–16 lowercase letters/digits.
- **id**: a random public identifier. Store it in plaintext and use it as the
  database lookup key, so verification is an O(1) row fetch, not a scan.
- **secret**: 256 bits of CSPRNG output. Only its keyed hash is stored.

## Issuing

```go
key, err := keyMod.Generate()
// Show key.Key to the user ONCE. It is never recoverable.
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

`Verify` first checks that the presented key has the shape `Generate` produces,
the same one `ParseID` accepts, and returns `false` for anything else, whatever
the stored hash holds. Before this check, a string such as a refresh token or the
empty string verified against its own hash, because the hash carries no label.
This is a minor breaking change for a caller that hashed a value of its own
making with `Hash` and verified it with `Verify`: only keys from `Generate` (or
with that shape) verify now. `Hash` still accepts any string.

> **Why not Argon2id?** An API key is 256 bits of random. Brute-forcing it is
> infeasible regardless of hash speed, and a per-request call must not pay
> Argon2id's cost. Keys are hashed with **keyed HMAC-SHA256**, peppered with the
> library's managed secret, so a leaked database of hashes is useless without
> the server secret too. (Passwords are different: they are low-entropy and use
> Argon2id; see [Password hashing](password.md).)

## Hashes share a key space with other modules

`apikey.Hash` is `HMAC-SHA256(secret, key)` with no label, and the secret is
the library's managed refresh secret, the same one `auth/credential`,
`auth/jwt` and `auth/totp` key their hashes with. A hash from one of these
modules is therefore a valid HMAC for some input of another. For example, the
hash `auth/credential` stores for a token is what `apikey.Hash` returns for a
string shaped like that module's framing (each of purpose, subject and token
preceded by its length as a big-endian `uint32`).

Nothing in the library compares a hash across modules, so nothing breaks by
itself. What you must not do is let your own code do it:

- Keep API-key hashes in their own column or table. Never keep them in the same
  column as credential, refresh-token or recovery-code hashes, and never look up
  a value in one kind of table with a hash taken from another.
- Do not call `Verify` with a stored hash that came from another module.
  `Verify` refuses a key that is not shaped like a generated one, but it cannot
  tell which module produced a hash.
- Look a key up by the id in its text first, then verify against that row's
  hash, as the example above does.

The hash is not changed, because every stored hash would stop matching. Giving
each module its own label belongs in a release that can say so and offer a
migration. `tests/hostile/credential` pins the current behaviour so a change to
it is deliberate.

## Revoking

Delete the row (or flag it) and check on lookup. There is no token to expire:
an API key lives until you remove it, so build rotation/expiry into your own
schema if you need it.
