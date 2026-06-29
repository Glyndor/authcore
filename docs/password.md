# Password hashing

`auth/password` hashes and verifies passwords with Argon2id in self-describing
PHC format — no algorithm choices, no boilerplate. See the
[error reference](errors.md) and the [runnable example](../examples/password/).

## Setup

```go
auth, err := authcore.New(authcore.DefaultConfig())

// Zero-config — OWASP-recommended Argon2id defaults applied automatically.
pwdMod, err := password.New(auth)
```

That's it. No config required.

> **Why Argon2id?** It's memory-hard: an attacker must allocate ~64 MiB of RAM
> *per attempt*, making GPU and ASIC brute-force attacks prohibitively expensive.
> bcrypt does not have this property.

## Hashing a password

```go
hash, err := pwdMod.Hash(userPassword)
switch {
case errors.Is(err, password.ErrWeakPassword):
    // 400 — tell the user exactly what's missing (message is descriptive)
case err != nil:
    // 500 — unexpected error
}
// Store hash in your database. Never store the plaintext.
db.StorePasswordHash(userID, hash)
```

`Hash` validates the password **before** spending CPU on hashing:

| Rule | Requirement |
|---|---|
| Length | 12 – 64 characters |
| Uppercase | At least one (`A`–`Z`, Unicode-aware) |
| Lowercase | At least one (`a`–`z`, Unicode-aware) |
| Digit | At least one (`0`–`9`) |
| Special | At least one (anything that is not a letter or digit) |

Each call also generates a **fresh random salt**, so two hashes of the same
password are always different strings — but both verify correctly.

The stored string is fully self-describing (**PHC format**):

```
$argon2id$v=19$m=65536,t=3,p=2$<base64-salt>$<base64-hash>
```

## Verifying a password

```go
ok, err := pwdMod.Verify(submittedPassword, storedHash)
switch {
case errors.Is(err, password.ErrInvalidHash):
    // 500 — hash in the database is malformed
case !ok:
    // 401 — wrong password
}
```

Comparison is **constant-time** (`crypto/subtle`) — timing attacks are not
possible. Parameters are always read from the stored hash, never from the
current module config, and **bounded to the same safe range** (`Memory` 8 MiB –
4 GiB, `Iterations` ≤ 20, `Parallelism` ≥ 1) so a corrupted or malicious stored
hash cannot force `argon2.IDKey` into an unbounded memory allocation.

> [!NOTE]
> Both `Hash` and `Verify` normalise plaintext to **Unicode NFC** before
> processing. A password like `café` hashes the same whether the user typed it
> on macOS (precomposed `é`) or Linux (decomposed `e` + combining acute), so
> cross-platform account access works out of the box.

## Tuning work parameters (optional)

The defaults are sized for 2 vCPUs / 4 GiB RAM. On more powerful hardware, crank
them up — a hash should take roughly 200–500 ms:

```go
pwdMod, err := password.New(auth, password.Config{
    Memory:      128 * 1024, // 128 MiB
    Iterations:  4,
    Parallelism: 4,          // match your guaranteed CPU core count
})
```

| Field | Default | Minimum |
|---|---|---|
| `Memory` | `65536` (64 MiB) | `8192` (8 MiB) |
| `Iterations` | `3` | `1` |
| `Parallelism` | `2` | `1` |

> **Old hashes stay valid.** All parameters live inside the hash string itself.
> Changing the config only affects *new* hashes — existing users keep working.

For migrating off bcrypt or another library without forcing a password reset,
see [Migrating](migrating.md).
