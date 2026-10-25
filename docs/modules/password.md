# Password hashing

`auth/password` hashes and verifies passwords with Argon2id in self-describing
PHC format. No algorithm choices, no boilerplate. See the
[error reference](../reference/errors.md) and the [runnable example](../../examples/modules/password/).

## Setup

```go
auth, err := authcore.New(authcore.DefaultConfig())

// Zero-config. OWASP-recommended Argon2id defaults applied automatically.
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
    // 400: tell the user exactly what's missing (message is descriptive)
case err != nil:
    // 500: unexpected error
}
if err != nil {
    return err // never store a failed hash
}
// Store hash in your database. Never store the plaintext.
db.StorePasswordHash(userID, hash)
```

`Hash` validates the password **before** spending CPU on hashing. The
defaults reproduce the policy the library has always enforced, and every
bound and required class is a [configurable policy field](../guides/configuration.md#the-principle),
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
- the other code points Unicode marks default-ignorable, such as the Hangul
  filler U+3164 and the combining grapheme joiner U+034F, and the blank
  braille pattern U+2800, all of which render as nothing
- every space other than the ASCII one, such as the no-break space U+00A0
- unassigned and private-use code points
- bytes that are not valid UTF-8, and the replacement character U+FFFD

Variation selectors (U+FE00 to U+FE0F, U+E0100 to U+E01EF and U+180B to U+180D)
are accepted: they follow emoji and some CJK characters, so refusing them would
reject passwords typed with an emoji keyboard.

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
password are always different strings, but both verify correctly.

The stored string is fully self-describing (**PHC format**):

```
$argon2id$v=19$m=65536,t=3,p=2$<base64-salt>$<base64-hash>
```

## Verifying a password

```go
ok, err := pwdMod.Verify(submittedPassword, storedHash)
switch {
case errors.Is(err, password.ErrInvalidHash):
    // 500: hash in the database is malformed
case !ok:
    // 401: wrong password
}
```

Comparison is **constant-time** (`crypto/subtle`). Timing attacks are not
possible. Parameters are always read from the stored hash, never from the
current module config, and **bounded** so a corrupted or malicious stored
hash cannot choose what a login costs. `Verify` returns `ErrInvalidHash`,
before it derives any key, for a hash that:

- is outside the format range (`Memory` 8 MiB to 4 GiB, `Iterations` 1 to 20,
  `Parallelism` 1 to 255), or
- asks for more than the module accepts, which is a ceiling derived from the
  module's own `Config`:

| Parameter | Ceiling |
|---|---|
| `Memory` | 128 times the configured `Memory`, and never above 1 GiB (1048576 KiB) |
| `Iterations` | 8 times the configured `Iterations`, and never above 20 |
| `Parallelism` | 8 times the configured `Parallelism`, and never above 255 |
| `Memory` x `Iterations` | at most 4 GiB-passes (4194304 KiB-passes) |

The multiples leave room for hashes made with a stronger work factor than
today's configuration, for example after lowering `Memory` on a smaller host.
The absolute 1 GiB limit applies to a hash the module did not configure, so a
hash cannot ask for more than that even when `Memory` is set high. A module
configured with a `Memory` above 1 GiB, or with a `Memory` x `Iterations`
product above 4 GiB-passes, raises those two limits to what it writes itself,
so it always verifies its own hashes. A hash made with a work factor above the
ceiling must be rehashed outside `Verify`, or the module configured with a
higher `Memory`, `Iterations` or `Parallelism`.

The three factor ceilings are applied one by one, so on their own they allow
1 GiB for 20 passes. The product limit closes that gap. Measured on a 16-core
x86-64 machine with `golang.org/x/crypto/argon2`:

| Stored cost | Time (1 lane) | Peak RSS | Accepted by default |
|---|---|---|---|
| 64 MiB x 3 passes (library default) | 0.08 s | 68 MB | yes |
| 1 GiB x 1 pass | 1.3 s | 1.05 GB | yes |
| 1 GiB x 4 passes (the worst accepted) | 3.7 s | 1.05 GB | yes |
| 1 GiB x 20 passes | 13.3 s | 1.05 GB | no, over the product limit |

The worst hash a default module derives a key for therefore costs about 3.7 s
of one core and 1 GiB. The OWASP password storage profiles and both RFC 9106
recommendations are below the product limit; the RFC 9106 first
recommendation (2 GiB, 1 pass) is above the default 1 GiB memory ceiling and
verifies under a module configured with that `Memory`. Rate-limit the login
endpoint regardless: a ceiling bounds one call, not the number of calls.

> [!NOTE]
> Both `Hash` and `Verify` normalise plaintext to **Unicode NFC** before
> processing. A password like `café` hashes the same whether the user typed it
> on macOS (precomposed `é`) or Linux (decomposed `e` + combining acute), so
> cross-platform account access works out of the box.

## Tuning work parameters (optional)

The defaults are sized for 2 vCPUs / 4 GiB RAM. On more powerful hardware, crank
them up. A hash should take roughly 200–500 ms:

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
> Changing the config only affects *new* hashes. Existing users keep working.

For migrating off bcrypt or another library without forcing a password reset,
see [Migrating](../guides/migrating.md).
