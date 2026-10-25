# Email & username validation

`auth/email` and `auth/username` validate and normalize user input into a
canonical form before you store it. See the [error reference](../reference/errors.md) and the
runnable [email](../../examples/modules/email/) and [username](../../examples/modules/username/)
examples.

## Email

### Setup

```go
emailMod, err := email.New(auth)
if err != nil {
    log.Fatal(err)
}
// Close is an optional no-op kept for backward compatibility. The module runs
// no background goroutine, so no cleanup is required.
```

### Validating and normalizing

Always call `ValidateAndNormalize` instead of validating and normalizing
separately. It lowercases, trims whitespace, and validates in a single call,
ensuring the value you store is always in canonical form:

```go
normalized, err := emailMod.ValidateAndNormalize(req.Email)
switch {
case errors.Is(err, email.ErrInvalidEmail):
    // 400: tell the user exactly what failed (message is descriptive)
    c.JSON(400, map[string]string{"error": errors.Unwrap(err).Error()})
    return
case err != nil:
    // 500: unexpected error
}
// Store normalized. Always lowercase, trimmed.
db.StoreUser(normalized, ...)
```

Validation rules (RFC 5321 / RFC 5322):

| Rule | Requirement |
|---|---|
| Total length | 1 – 254 characters |
| Format | One `@` separating a non-empty local part and domain |
| Local part | ≤ 64 characters |
| Domain | At least one dot; no leading, trailing, or consecutive dots |
| Domain labels | 1 – 63 characters each |

> **Always normalize before storing and before querying.** This ensures
> consistent lookup: `User@EXAMPLE.COM` and `user@example.com` are the same
> address.

### Plus-addressing

Plus-addressing (`user+tag@example.com`) is accepted by default: this is an
[open policy field](configuration.md#the-principle). A deployment that
treats `(local, domain)` as the unique account key and wants one mailbox to
be unable to own N accounts can refuse plus-addressing:

```go
emailMod, err := email.NewWithConfig(auth, email.Config{
    RejectPlusAddressing: true,
})
// user+tag@example.com is now rejected with the reason "plus-addressing
// is not allowed".
```

The structural validation (RFC 5321/5322, IDN punycode, domain rules) is
unaffected.

> [!NOTE]
> **Internationalised domains (IDN)** are supported. Unicode domains are
> converted to ASCII punycode during normalisation:
>
> ```
> user@münchen.de  →  user@xn--mnchen-3ya.de
> user@例え.jp     →  user@xn--r8jz45g.jp
> ```
>
> Store the ASCII form so DNS lookups and database comparisons are deterministic.

### Look-alike characters in the local part

The local part is opaque. `ValidateAndNormalize` brings it to NFC and
lowercases it, and refuses invisible and control characters, but it does **not**
fold characters that only look alike. `аlice@example.com` (Cyrillic `а`,
U+0430) and `alice@example.com` (Latin `a`) are two different addresses and
both are accepted. This is by design: the local part is opaque (RFC 5321) and
only the receiving server knows which spellings reach the same mailbox, so the
library has no sound folding rule to apply.

If you need robust uniqueness, or must stop an attacker from registering a
look-alike of an existing address, apply your own policy before you store it.
For example, restrict the local part to ASCII, or reject a local part that mixes
scripts. The domain does not have this problem: it is converted to punycode, so
a look-alike domain is stored as its `xn--` form and is not equal to the real
one. The behaviour is pinned by a test in `tests/hostile/identity`, so a change
to it is a deliberate, visible one.

### Verifying a domain can receive email

`VerifyDomain` performs an optional DNS MX lookup to confirm the domain is
configured to receive email. Call it after `ValidateAndNormalize` when you want
to reject obviously fake domains before sending a verification email.

Results are cached per domain (default 5 minutes) and DNS lookups for the same
domain are deduplicated via `singleflight`. Safe for high-concurrency workloads.

```go
ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
defer cancel()

err = emailMod.VerifyDomain(ctx, normalized)
switch {
case errors.Is(err, email.ErrDomainNoMX):
    // 400: domain exists but cannot receive email
    c.JSON(400, map[string]string{"error": "email domain cannot receive messages"})
    return
case errors.Is(err, email.ErrDomainUnresolvable):
    // DNS lookup failed. Do NOT block the user; log and continue
    log.Warn("DNS check unavailable: %v", err)
}
```

> **`ErrDomainUnresolvable` is a soft failure.** DNS can be temporarily
> unavailable due to network issues unrelated to the user's input. Never block a
> registration on this error: log it and proceed.

## Username

### Setup

```go
userMod, err := username.New(auth)
if err != nil {
    log.Fatal(err)
}
```

### Validating and normalizing

Always call `ValidateAndNormalize`. It lowercases, trims whitespace, and
validates in a single call, ensuring the value you store is always in canonical
form:

```go
normalized, err := userMod.ValidateAndNormalize(req.Username)
if err != nil {
    // errors.Unwrap(err).Error() contains the specific rule that failed.
    c.JSON(400, map[string]string{"error": errors.Unwrap(err).Error()})
    return
}
db.StoreUser(normalized, ...) // always lowercase, trimmed, validated
```

Validation rules:

| Rule | Default |
|---|---|
| Length | `MinLength` – `MaxLength` (default 3 – 32 characters) |
| Allowed characters | `[a-z0-9_-]` only (closed - the homoglyph control) |
| First character | Letter or digit (not `_` or `-`) |
| Last character | Letter or digit (not `_` or `-`) |
| Consecutive specials | `__`, `--`, `_-`, `-_` are rejected |
| Reserved names | Built-in blocklist, extended with `Config.ExtraReservedNames` and trimmed with `Config.AllowReservedNames` |

The length bounds and the reserved-names list are
[configurable policy fields](configuration.md#the-principle). The
character set, normalisation, and consecutive-specials rule stay closed - 
widening the character set to Unicode is exactly what enables
homoglyph impersonation, and is the part of the module that *is* a
security standard rather than a product default.

> **Always normalize before storing and before querying.** `Alice123` and
> `alice123` are the same username. Store only the canonical (normalized) form.
