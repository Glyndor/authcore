# Username validation

`auth/username` validates and normalizes usernames into a canonical form
before you store them, and refuses reserved names. See the
[error reference](../reference/errors.md) and the
[runnable example](../../examples/modules/username/).

## Setup

```go
userMod, err := username.New(auth)
if err != nil {
    log.Fatal(err)
}
```

## Validating and normalizing

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
[configurable policy fields](../guides/configuration.md#the-principle). The
character set, normalisation, and consecutive-specials rule stay closed - 
widening the character set to Unicode is exactly what enables
homoglyph impersonation, and is the part of the module that *is* a
security standard rather than a product default.

> **Always normalize before storing and before querying.** `Alice123` and
> `alice123` are the same username. Store only the canonical (normalized) form.
