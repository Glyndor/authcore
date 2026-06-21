# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Changed

- **BREAKING — module path renamed** from `github.com/Jaro-c/authcore` to
  `github.com/Glyndor/authcore`. Update your imports and re-run
  `go get github.com/Glyndor/authcore`. This is a new module identity, not a
  `/v2`: the library stays on `v1.x` and the old path is frozen at its last
  published version, receiving no further updates — move to the new path to
  keep getting fixes.
- JWT default `Issuer` and `Audience` now read `github.com/Glyndor/authcore`,
  following the new module identity.

---

## [1.2.2] - 2026-04-26

Dependency-update release. No public API changes; safe drop-in upgrade.

### Changed

- **`golang.org/x/net`** bumped from v0.51.0 to v0.53.0 (includes HTTP/2 and
  networking security fixes).
- **`golang.org/x/text`** bumped from v0.35.0 to v0.36.0 (Unicode handling
  fixes).
- **GitHub Actions** — `actions/checkout`, `codecov/codecov-action`,
  `actions/upload-artifact`, `actions/stale`, and `securego/gosec` pinned to
  latest releases via Dependabot.

---

## [1.2.1] - 2026-04-19

Documentation-only release. No code behaviour changes; safe drop-in upgrade.

### Fixed

- **`README.md` — API Stability section** no longer claims the library is
  pre-v1 ("v0.x (current)"). The versioning policy now describes the real
  v1.x guarantees and references the v1.2.0 defence-in-depth additions.
- **`SECURITY.md` — Supported Versions** no longer frames "stable v1.0.0"
  as a future event. Current v1.x support is documented with a non-
  breaking-upgrade guarantee and a pointer to the CHANGELOG for
  validation-tightening releases.
- **`CODE_OF_CONDUCT.md` — Enforcement** Code-of-Conduct reports used to be
  routed to GitHub's *security* advisory page. They are now routed to the
  maintainer directly; the private advisory is retained only as a
  clearly-flagged fallback for reporters who cannot contact the
  maintainer privately any other way.

### Changed — godoc clarifications

- **`auth/jwt/config.go` — `Audience`** field docs now state explicitly
  that only the first value is enforced on verification, and that it is
  snapshotted into a private field at `New()` so callers who later mutate
  the slice cannot weaken the verifier (behaviour introduced in v1.2.0).
- **`auth/password/password.go` — `Verify`** docs now list the exact PHC
  parameter ranges the function enforces (Memory 8 MiB – 4 GiB,
  Iterations 1 – 20, Parallelism ≥ 1) instead of the vague "supported
  range" language.
- **`internal/keymanager` package doc** now documents the 4 KiB key-file
  size cap and its rationale (previously visible only in `generate.go`).

Tests for the corresponding behaviour in v1.2.0 and the new edge-case
coverage landed earlier in this release series; no new tests ship with
v1.2.1.

---

## [1.2.0] - 2026-04-19

Defence-in-depth release. Five complementary validations close the last
round of edge cases flagged in the pre-v1 gap audit. No public API changes;
existing callers upgrade without modification, although the tightened
validation can reject configurations or inputs that were previously
silently accepted.

### Added

#### JWT module (`github.com/Glyndor/authcore/auth/jwt`)
- `validateConfig` now caps `AccessTokenTTL` at **24 hours** and
  `RefreshTokenTTL` at **365 days**. Prevents operators from accidentally
  issuing effectively permanent bearer tokens by typing the wrong unit.
- `VerifyAccessToken` / `RotateTokens` now assert that the token's JOSE
  `kid` header matches the module's current key id. Unknown kids return
  `ErrTokenInvalid`. Future-proofs multi-key rotation.

#### Password module (`github.com/Glyndor/authcore/auth/password`)
- `Hash`, `Verify`, and `ValidatePolicy` now normalise plaintext to
  Unicode **NFC** before hashing or policy checks. A user who registers
  on macOS (precomposed accents) can now sign in on Linux (decomposed
  form) without being locked out.

#### Email module (`github.com/Glyndor/authcore/auth/email`)
- `ValidateAndNormalize` now converts Unicode domain parts to their
  ASCII (**punycode**) form via `golang.org/x/net/idna` before
  validation. Users with legitimate internationalised domains
  (`münchen.de`, `例え.jp`) can now register. The stored canonical
  form is always ASCII, so the downstream DNS MX lookup resolves it.

#### Key manager (`internal/keymanager`)
- All key-loading paths now share a `readCapped` helper that rejects
  any key file larger than 4 KiB (healthy Ed25519 PEM is ~200 bytes).
  Protects startup from a corrupted or attacker-replaced key file
  that would otherwise be loaded whole into memory before
  `pem.Decode` rejects it.

### Dependencies

- Added `golang.org/x/net v0.51.0` for IDN (punycode) support.
  Post-GO-2026-4559, not affected by the advisory.
- Added `golang.org/x/text v0.35.0` for Unicode NFC normalisation.

---

## [1.1.2] - 2026-04-19

Security-hardening release. No public API changes; existing callers upgrade
without modification. Two verification paths are now stricter, which can
reject previously-accepted tokens and stored hashes that were produced under
inconsistent configuration.

### Security

#### JWT module (`github.com/Glyndor/authcore/auth/jwt`)
- `VerifyAccessToken` and `RotateTokens` now enforce the `iss` claim against
  `Config.Issuer`, mirroring the existing `aud` check. Previously, a token
  signed by a trusted key was accepted regardless of which service issued it
  — a cross-service key-reuse gap. Tokens with a mismatched issuer now return
  `ErrTokenInvalid`.

#### Password module (`github.com/Glyndor/authcore/auth/password`)
- `parsePHC` now bounds the `m=` (memory), `t=` (iterations), and `p=`
  (parallelism) parameters read from the stored hash to the same ceilings
  `validateConfig` enforces at construction time. A corrupted or attacker-
  supplied hash of the form `$argon2id$v=19$m=4000000000,…` previously caused
  `argon2.IDKey` to attempt a multi-TiB allocation and crash the process on
  `Verify`; such hashes now return `ErrInvalidHash` before any key derivation.

### Hardening

#### JWT module
- `verifyAccessToken` / `verifyRefreshToken` internal helpers take
  `audience string` (previously `[]string`). The module snapshots
  `Config.Audience[0]` into a private `primaryAudience` field at
  construction, making the verify path immune to post-init mutation of the
  caller's audience slice.

### Fixed

- `module.go` constructor convention comment now lists the actual
  per-module signatures (`jwt.New[T]`, variadic `password.New`, variadic
  `email.New`, `username.New(p)` only) instead of the outdated
  one-size-fits-all form.

---

## [1.0.0] - 2026-03-14

First stable release. The public API is now frozen under the guarantees of
semantic versioning — no breaking changes will be introduced without a major
version bump.

### Added

#### Core (`github.com/Glyndor/authcore`)
- `New(cfg Config) (*AuthCore, error)` — initialises the library, applies
  defaults, validates configuration, selects logger, and sets up the key manager.
- `DefaultConfig() Config` — returns production-ready defaults
  (`EnableLogs=true`, `Timezone=UTC`, `KeysDir=".authcore"`).
- `Config`, `Logger`, `Keys`, `Provider`, `Module` interfaces — the stable
  extension points for all authentication modules.
- Automatic Ed25519 key-pair generation and persistence on first run
  (`ed25519_private.pem` / `ed25519_public.pem`, mode `0600` / `0644`).
- Automatic HMAC-SHA256 refresh-secret generation (`refresh_secret.key`,
  mode `0600`, 32 bytes / 256 bits of entropy).
- Catch-all `.gitignore` written to `KeysDir` to prevent accidental commits
  of key material.
- Pluggable logger — pass any `authcore.Logger` implementation via
  `Config.Logger`; falls back to a stdlib logger or a silent no-op.
- Timezone-aware `Clock` abstraction (`internal/clock`) for deterministic
  testing without wall-clock sleeps.

#### JWT module (`github.com/Glyndor/authcore/auth/jwt`)
- `New[T](p Provider, cfg Config) (*JWT[T], error)` — creates the JWT module;
  `T` is the application-specific claims type embedded in access tokens.
- `DefaultConfig() Config` — returns safe defaults
  (`AccessTokenTTL=15m`, `RefreshTokenTTL=24h`, `ClockSkewLeeway=0`).
- `(*JWT[T]).CreateTokens(subject, extra T) (*TokenPair, error)` — issues an
  EdDSA-signed (Ed25519) access + refresh token pair. Subject must be a
  UUID v7 (RFC 9562 §5.7).
- `(*JWT[T]).VerifyAccessToken(token) (*Claims[T], error)` — verifies
  signature, expiry, audience, and token type; returns typed claims.
- `(*JWT[T]).HashRefreshToken(token) string` — returns the HMAC-SHA256 hex
  digest of a refresh token for safe database storage.
- `(*JWT[T]).VerifyRefreshTokenHash(token, storedHash string) bool` —
  constant-time comparison (`crypto/subtle`) of a token against its stored
  hash; prevents timing attacks on database lookups.
- `(*JWT[T]).RotateTokens(refreshToken, extra T) (*TokenPair, error)` —
  verifies a refresh token and issues a fresh token pair with updated claims.
- `Config.ClockSkewLeeway time.Duration` — tolerates small clock drift between
  distributed servers during token verification.
- UUID v7 `jti` generation (RFC 9562 §5.7) — time-ordered, sortable session
  identifiers with 80 bits of cryptographic randomness.
- `kid` JOSE header derived from `SHA-256(publicKey)[:8]` — enables
  zero-downtime key rotation.
- Sentinel errors: `ErrTokenExpired`, `ErrTokenInvalid`, `ErrTokenMalformed`,
  `ErrWrongTokenType`, `ErrInvalidSubject`, `ErrInvalidConfig`.

### Security

- All random material generated with `crypto/rand` (OS entropy source).
- Private key and refresh secret stored with mode `0600` (owner-read only).
- Refresh token never stored in plaintext — only the HMAC-SHA256 digest is
  returned to the caller.
- Algorithm enforcement: `eddsaKeyFunc` rejects any token whose JOSE header
  does not specify `alg=EdDSA`, closing algorithm-confusion attack vectors.

---

## [1.1.1] - 2026-03-15

### Added

#### Password (`auth/password`)
- `(*Password).ValidatePolicy(plaintext string) error` — exposes the built-in
  policy check as a public method for fail-fast validation in HTTP handlers,
  before spending CPU on Argon2id.

---

## [1.1.0] - 2026-03-14

### Added

#### Password module (`github.com/Glyndor/authcore/auth/password`)
- `New(p Provider, cfg ...Config) (*Password, error)` — creates the password
  module. Config is optional; omitting it applies OWASP-recommended defaults.
- `DefaultConfig() Config` — returns OWASP-recommended Argon2id defaults
  (`Memory=64MiB`, `Iterations=3`, `Parallelism=2`).
- `(*Password).Hash(plaintext string) (string, error)` — validates the
  password against the built-in policy, then derives an Argon2id hash with a
  fresh random salt and returns it in PHC string format.
- `(*Password).Verify(plaintext, phcHash string) (bool, error)` — verifies a
  password against a stored PHC hash using constant-time comparison
  (`crypto/subtle`). Parameters are read from the stored hash, so existing
  hashes remain valid after the module's Config is updated.
- Built-in password policy enforced in `Hash`: 12–64 characters, at least one
  uppercase letter, one lowercase letter, one digit, and one special character.
  Disable via `Config.DisablePolicy` for migration scenarios.
- Sentinel errors: `ErrInvalidConfig`, `ErrInvalidHash`, `ErrWeakPassword`.

### Security

- Updated `golang.org/x/crypto` to v0.45.0, patching three vulnerabilities in
  the `ssh` and `ssh/agent` packages (GO-2025-4116, GO-2025-4134, GO-2025-4135).
  None affected authcore's code paths.
- Raised minimum Go version to 1.26.1, patching five standard library
  vulnerabilities (GO-2026-4599 to GO-2026-4603). None affected authcore's
  code paths.

### Fixed

- Corrected four documentation inaccuracies found during audit:
  - `CreateTokens` docstring referenced non-existent `pair.AccessTokenID` field.
  - `CreateTokens` docstring described `SessionID` as the refresh token's jti;
    it is in fact shared by both the access and refresh tokens.
  - `refreshClaims` internal comment incorrectly stated "no iat claim"; the
    refresh token does include an `iat` claim.
  - `module.go` did not list `auth/password` as an available implementation and
    showed an outdated constructor signature.

---

## [Unreleased]

### Planned

- `auth/apikey` — opaque API-key generation with pluggable store interface.
- `auth/oauth` — OAuth 2.0 / OIDC provider integration.
- Key rotation helpers — zero-downtime rotation utilities.
