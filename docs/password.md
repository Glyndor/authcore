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

`Hash` validates the password **before** spending CPU on hashing. The
defaults reproduce the policy the library has always enforced, and every
bound and required class is a [configurable policy field](configuration.md#the-principle),
not a security primitive:

| Rule | Default |
|---|---|
| Length | `MinLength` – `MaxLength` (default 12 – 64 characters) |
| Uppercase | `RequireUpper` (default `true`) |
| Lowercase | `RequireLower` (default `true`) |
| Digit | `RequireDigit` (default `true`) |
| Special | `RequireSymbol` (default `true`) |

The classes follow Unicode. Uppercase and lowercase are cased letters in any
script, a digit is any decimal digit, and a **special character is
punctuation, a symbol, or the ASCII space** (`!`, `-`, `+`, `€`, `¿`, ` `).
A printable character outside the four classes is allowed and satisfies none
of them: a letter without case such as `漢` or `א`, a combining mark, or a
number like `½` does not count as special.

### Characters that are never accepted

One rule is not a policy field. `Hash` and `ValidatePolicy` refuse any
character that is not printable, under every `Config`, including one with all
four `Require*` fields off:

- control characters: NUL, tab, newline, DEL and the rest of C0 and C1
- invisible format characters, such as the zero-width joiner U+200D
- every space other than the ASCII one, such as the no-break space U+00A0
- unassigned and private-use code points
- bytes that are not valid UTF-8, and the replacement character U+FFFD

Validation checks length first, after NFC normalization. An input below
`MinLength` or above `MaxLength` returns `ErrWeakPassword` with the length
reason, even if it also contains a non-printable character. Once length passes,
the printable-character check runs before the required character classes and
returns `ErrWeakPassword` wrapping `ErrNonPrintableCharacter` on failure. You
can use that sentinel to explain that a paste carried a character the user
cannot see:

```go
err := pwdMod.ValidatePolicy(req.Password)
switch {
case errors.Is(err, password.ErrNonPrintableCharacter):
    // 400: "must contain only printable characters"
case errors.Is(err, password.ErrWeakPassword):
    // 400: errors.Unwrap(err).Error() names the rule
}
```

Check it before the general case: both `errors.Is` calls are true for this
error.

Until this rule existed, `Abcdefghijk1` was rejected for having no special
character while `Abcdefghijk1` followed by a NUL byte was accepted, hashed and
verified, because the NUL counted as the special character. A byte like that
is the one a terminal, a transport or a database column is most likely to
strip later, and then the user cannot sign in.

> [!IMPORTANT]
> The rule applies when a password is **set**, never when it is checked.
> `Verify` runs no policy, so a user whose stored password already holds such
> a character keeps signing in with it. They are asked for a printable
> password the next time they change it.

Each `Require*` field is a `*bool`, so that leaving it unset ("keep the
default") stays distinguishable from setting it to false ("turn this class
off"). Use `password.Bool` rather than a temporary local:

```go
cfg := password.DefaultConfig()
cfg.MinLength = 16
cfg.RequireSymbol = password.Bool(false) // no symbol required
pwdMod, err := password.New(auth, cfg)
```

`ValidatePolicy` reports the rule that was violated in the error message
("must be at least 16 characters" when you raise `MinLength` to 16, for
example), so the message you show the user always matches what you
configured.

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
