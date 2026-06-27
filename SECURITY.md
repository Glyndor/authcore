# Security Policy

## Supported Versions

Security fixes are backported to the latest minor line of each supported major version. Older lines are expected to upgrade to the current minor.

| Major line | Supported | Notes |
|------------|-----------|-------|
| `v1.x`     | ✅        | Current. Latest minor receives all security fixes. |
| `< v1.0`   | ❌        | Pre-release; no longer supported. |

Upgrading within `v1.x` is non-breaking by semver guarantee. Patch releases may tighten validation (e.g. `v1.2.0` added TTL caps, `kid` matching, and other defence-in-depth checks) — review the [CHANGELOG](CHANGELOG.md) for behaviour that is now stricter.

A formal long-term support window for specific minor lines will be defined if usage patterns make it necessary; until then, always upgrade to the latest tagged `v1.x` release.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Please report security issues via [GitHub private vulnerability reporting](https://github.com/Glyndor/authcore/security/advisories/new).
This keeps the details confidential until a patch is released.

Include as much of the following as possible:

- A clear description of the vulnerability and its potential impact.
- Steps to reproduce or a minimal proof-of-concept (PoC).
- The affected version(s) — output of `go list -m github.com/Glyndor/authcore`.
- Any known mitigations or workarounds.

You will receive an acknowledgement within **72 hours**.
We aim to release a patch within **14 days** for confirmed critical issues and **30 days** for non-critical ones.
Reporters will be credited in the release notes unless you prefer to remain anonymous.

## Scope

This policy covers the `github.com/Glyndor/authcore` module and all published sub-packages in this repository, including:

- `auth/jwt`
- `auth/password`
- `auth/email`
- `auth/username`

Planned modules listed in the README roadmap join this scope as soon as they are published.

Third-party dependencies are out of scope — please report those issues to their respective maintainers.

## Disclosure Policy

We follow coordinated disclosure:

1. Reporter submits the vulnerability privately.
2. Maintainers confirm and reproduce the issue within 72 hours.
3. A fix is developed in a private branch.
4. A patched release is published.
5. A public security advisory is opened with full details.

## Security Best Practices for Users

- Always use the latest published version of authcore.
- Pin your dependency with `go.sum` and verify checksums via the Go module proxy.
- Never store raw refresh tokens — always store only the `RefreshTokenHash` value.
- Protect your `KeysDir` (default `.authcore`) with filesystem permissions; never commit it.
- Set `ClockSkewLeeway` to the minimum value needed for your deployment — larger windows reduce the security margin of short-lived tokens.
