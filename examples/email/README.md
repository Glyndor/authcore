# auth/email — validation, normalization, DNS MX

Validate + normalize an address in one call, optionally verify its domain can receive mail.

## Run

```bash
go run ./examples/email
```

> The `VerifyDomain` step performs a real DNS lookup. It is skipped automatically if your network has no outbound DNS access.

## What it shows

| Step | API |
|---|---|
| Normalize + validate in one call — always store the canonical form | `emailMod.ValidateAndNormalize(input)` |
| Rejection reasons — RFC 5321/5322 rules, descriptive errors | `errors.Unwrap(err).Error()` |
| DNS MX verification — cached per domain, `singleflight`-deduplicated | `emailMod.VerifyDomain(ctx, addr)` |
| Soft-fail handling — `ErrDomainUnresolvable` means "DNS is down", not "email is bad" | `errors.Is(err, email.ErrDomainUnresolvable)` |

## Expected output (abridged)

```
=== ValidateAndNormalize ===
accepted  "  USER@EXAMPLE.COM  " → "user@example.com"
accepted  "user.name+tag@sub.example.co.uk" → "user.name+tag@sub.example.co.uk"
rejected  "" → must not be empty
rejected  "notanemail" → invalid format
rejected  "user@localhost" → domain must contain at least one dot
rejected  "user@example..com" → invalid format

=== VerifyDomain ===
domain OK     : user@gmail.com

=== Error handling ===
ErrInvalidEmail: email: invalid address: invalid format
reason only   : invalid format
```

## Golden rule

Always normalize **before storing** and **before querying** the database. `User@EXAMPLE.COM` and `user@example.com` are the same address — store only the canonical form.
