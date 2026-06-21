# auth/password — Argon2id hashing example

Policy check → hash → verify → error handling → custom work parameters.

## Run

```bash
go run ./examples/password
```

## What it shows

| Step | API |
|---|---|
| Policy validation — weak passwords are rejected *before* any CPU is spent | `pwdMod.Hash(weak)` → `ErrWeakPassword` |
| Hashing — 64 MiB Argon2id, PHC-encoded output | `pwdMod.Hash(strong)` |
| Verification — constant-time comparison, parameters read from the stored hash | `pwdMod.Verify(plain, hash)` |
| Error handling — malformed hashes return `ErrInvalidHash` | `errors.Is(err, password.ErrInvalidHash)` |
| Tuning — scale `Memory`, `Iterations`, `Parallelism` for your hardware | `password.New(auth, password.Config{…})` |

## Expected output (abridged)

```
=== Policy validation ===
rejected  : password: does not meet policy requirements: must be at least 12 characters
accepted  : Str0ng-P@ssword!

=== Hashing ===
stored hash: $argon2id$v=19$m=65536,t=3,p=2$OUz5NhK5p0CQauGq2cB0eA$A8OffcIAr5jSM/qWrp0/sYS8t62kGT/BaXNF8kV1oYs

=== Verification ===
correct password : true
wrong password   : false

=== Error handling ===
ErrInvalidHash caught correctly

=== Custom parameters ===
128 MiB hash: $argon2id$v=19$m=131072,t=4,p=4$…
```

Each run produces a **different** hash string for the same password — every call generates a fresh random salt.

## Why Argon2id?

Memory-hard: an attacker must allocate ~64 MiB per attempt, which makes GPU and ASIC brute-force attacks prohibitively expensive. bcrypt does not have this property.
