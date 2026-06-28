# auth/username — validation, normalization, reserved names

Validate + normalize a handle in one call, reject reserved names like `admin`, `root`, `login`.

## Run

```bash
go run ./examples/username
```

## What it shows

| Step | API |
|---|---|
| Normalize + validate in one call | `userMod.ValidateAndNormalize(input)` |
| Character rules (`[a-z0-9_-]`, no consecutive specials, length 3–32) | `errors.Unwrap(err).Error()` |
| Reserved-name blocklist (built-in, fixed) | `username.ErrInvalidUsername` |
| Idempotent normalization — `Alice_Dev99` and `alice_dev99` collapse to the same canonical form |

## Expected output (abridged)

```
=== ValidateAndNormalize ===
accepted  "  Alice_123  "      → "alice_123"
accepted  "bob-dev"            → "bob-dev"
accepted  "user99"             → "user99"
rejected  "ab"                 → must be at least 3 characters
rejected  "-alice"             → must start with a letter or digit
rejected  "alice__bob"         → must not contain consecutive underscores or hyphens
rejected  "alice@bob"          → may only contain letters, digits, underscores, and hyphens
rejected  "admin"              → "admin" is a reserved name
rejected  "root"               → "root" is a reserved name

=== Registration flow ===
raw input  : "  Alice_Dev99  "
stored as  : "alice_dev99"

=== Error handling ===
ErrInvalidUsername: username: invalid username: "admin" is a reserved name
reason only       : "admin" is a reserved name
```

## Golden rule

Always normalize **before storing** and **before querying** — two users should never differ only in casing or whitespace.
