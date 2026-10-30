# Testing, modules & layout

## Testing your auth layer

Every authcore module accepts a `Provider` interface, not a concrete
`*AuthCore`, which means **you never need to generate real keys or touch the
disk in tests**. Pass in a stub.

```go
package mypkg_test

import (
    "crypto/ed25519"
    "testing"

    "github.com/Glyndor/authcore"
    "github.com/Glyndor/authcore/auth/jwt"
)

// stubProvider implements authcore.Provider with fixed, in-memory dependencies.
type stubProvider struct {
    cfg    authcore.Config
    logger authcore.Logger
    keys   authcore.Keys
}

func (s *stubProvider) Config() authcore.Config { return s.cfg }
func (s *stubProvider) Logger() authcore.Logger { return s.logger }
func (s *stubProvider) Keys() authcore.Keys     { return s.keys }

// stubKeys satisfies authcore.Keys with values you control in the test.
type stubKeys struct {
    priv   ed25519.PrivateKey
    pub    ed25519.PublicKey
    secret []byte
    kid    string
}

func (k *stubKeys) PrivateKey() ed25519.PrivateKey { return k.priv }
func (k *stubKeys) PublicKey() ed25519.PublicKey   { return k.pub }
func (k *stubKeys) RefreshSecret() []byte          { return k.secret }
func (k *stubKeys) KeyID() string                  { return k.kid }

func TestMyHandler(t *testing.T) {
    pub, priv, _ := ed25519.GenerateKey(nil)
    p := &stubProvider{
        cfg:    authcore.DefaultConfig(),
        logger: &noopLogger{},
        keys:   &stubKeys{priv: priv, pub: pub, secret: []byte("test-secret-32-bytes-long-xxxxxx"), kid: "test"},
    }

    jwtMod, err := jwt.New[struct{}](p, jwt.DefaultConfig())
    if err != nil {
        t.Fatal(err)
    }
    _ = jwtMod // ... exercise your handler against jwtMod, with no file I/O.
}
```

> [!TIP]
> For deterministic time in tests (e.g. to assert `ExpiresAt`), override
> `Config.Timezone` and use `time.Now()` equivalents through the same clock your
> production code reads from.

## Writing a module

Modules depend on `authcore.Provider`, not the concrete `*AuthCore`, so they
remain independently testable without touching the filesystem or generating real
keys.

```go
// Provider is the narrow interface that *AuthCore satisfies.
type Provider interface {
    Config() Config  // shared configuration
    Logger() Logger  // shared logger sink
    Keys()   Keys    // Ed25519 keys + HMAC secret
}

// Module is the marker interface every sub-module must implement.
type Module interface {
    Name() string // stable, lowercase identifier e.g. "jwt"
}
```

Minimal module skeleton:

```go
package mypkg

import "github.com/Glyndor/authcore"

type MyModule struct {
    log authcore.Logger
    // ...
}

func New(p authcore.Provider, cfg Config) (*MyModule, error) {
    return &MyModule{log: p.Logger()}, nil
}

func (m *MyModule) Name() string { return "mypkg" }
```

In tests, inject a stub `Provider` that returns fixed keys. No disk I/O
required.

## Project layout

```
authcore/
├── authcore.go          # New() · AuthCore struct · compile-time interface assertions
├── config.go            # Config · DefaultConfig()
├── logger.go            # Logger interface · picks the implementation from Config
├── keystore.go          # KeyStore interface · NewKeyStoreFromKeys / NewKeyStoreFromPEM
├── keystore_disk.go     # The default store: keys under Config.KeysDir
├── keystore_static.go   # Stores built from keys or PEM held in memory
├── module.go            # Keys · Provider · Module interfaces
├── errors.go            # Sentinel errors
│
├── .github/workflows/   # Flat on purpose: GitHub only registers workflows at this level
│                        # (a workflow in .github/workflows/nested/ was pushed on 2026-10-25 and never
│                        # appeared in `gh workflow list`), so it cannot be split into subfolders
│
├── cmd/
│   └── authcore-keygen/ # Writes a key set into a new directory (see the container guide)
├── scripts/             # The CI selectors and gates, each with its own test script:
│                        # ci-decide/, api-compat/, folder-limit/, release-notes/
├── tests/
│   ├── hostile/         # Attacks on each module and on the modules in composition, one folder per module
│   └── meta/            # Checks on the repository itself: documentation scope, fuzz wiring
│
├── internal/
│   ├── clock/           # Timezone-aware Clock: injected for deterministic tests
│   ├── keystore/
│   │   ├── contract/    # The checks New runs on what a KeyStore returned
│   │   ├── keysdir/     # Config.KeysDir checks: create, or load-only
│   │   └── disk/        # The default disk store over the key manager
│   ├── logging/         # The built-in stdlib and noop loggers
│   └── keymanager/      # Ed25519 + HMAC key generation, persistence, validation
│       ├── bootstrap/   # New: prepare the directory, then generate, recover or load
│       ├── keyload/     # Reading a key set back from disk (loadonly/: the load-only entry point; keyloadtest/: test support)
│       ├── staging/     # Publishing a fresh key set (createset/: staging directory, linkkeys/: hard links, preflight/: symlink refusal; stagingtest/: test support)
│       ├── recovery/    # Finishing or refusing an interrupted publish (match/: find the staging, complete/: link it into place, leftovers/: report, wait/: wait for the winner)
│       ├── redact/      # Secret-free rendering behind the facade's fmt.Formatter
│       ├── metadata/    # metadata.json: the on-disk layout marker
│       ├── fsguard/     # Classifying managed files; exclusive create; set inspection
│       ├── fileio/      # Size-capped read, durable write, directory sync
│       ├── modecheck/   # Permission warnings and directory tightening
│       ├── pemcodec/    # PKCS#8 / PKIX PEM encoding and strict decoding
│       ├── material/    # Validating in-memory key material; key id derivation
│       ├── refusals/    # The wording of every "will not touch this directory" error
│       ├── layout/      # File names, modes, size cap, the Logger interface
│       └── seams/       # Test-only fault and hard-link hooks
│
├── auth/
│   ├── jwt/             # JSON Web Token authentication (EdDSA / Ed25519)
│   │   └── internal/
│   │       ├── issue/        # Signing the access and refresh pair of a session
│   │       ├── parse/        # Token shape, signature and registered claims (errmap/: golang-jwt errors to sentinels, keyfunc/: EdDSA key selection by kid)
│   │       ├── verify/       # Token kind and denylist check on top of a parsed token
│   │       ├── rotation/     # Exchanging a refresh token for a new pair
│   │       ├── refreshhash/  # HMAC-SHA256 digest of a refresh token and its comparison
│   │       ├── denylist/     # The optional revocation hook and its default deadline
│   │       ├── claims/       # Access and refresh claim sets, token types, size cap
│   │       ├── jwterr/       # The sentinel errors the jwt package re-exports
│   │       ├── tokenid/      # UUID v7 checks, session ids and refresh-token rids
│   │       ├── vkey/         # Refusing public keys that cannot be trusted
│   │       └── jwttest/      # Test-only fixtures: keys, provider, a clock-driven rig
│   ├── password/        # Argon2id password hashing (internal/: kdf, phc, policy)
│   ├── email/           # Email validation, normalization, DNS MX verification (internal/: errs, localpart, normalize, syntax, mx; mx/: cache, domain, answer)
│   ├── totp/            # TOTP codes and recovery codes (internal/: hotp, secret, otpauth, recovery, verifier)
│   ├── username/        # Username validation, normalization (internal/reserved: the blocklist)
│   ├── apikey/          # Opaque API keys (internal/: format, digest)
│   ├── credential/      # Single-use, time-bound tokens (internal/: binding, expiry)
│   ├── field/           # Field encryption and blind index (internal/: kdf, seal, blind)
│   └── oauth/           # OpenID Connect / OAuth2 client (social login)
│       └── internal/
│           ├── idtoken/      # ID token verification (claimread/: typed claim readers, keyissuer/: the signing key's issuer)
│           ├── jwks/         # Signing-key cache: TTL, refresh cooldown, selection (candidate/: per-key restrictions, fetch/: download and size cap, jwk/: JWK parsing)
│           ├── discovery/ exchange/ userinfo/ apple/ clientauth/ issuer/ pkce/ redirect/ urlcheck/   # the rest of the flow
│           └── oauthtest/    # Test-only fixtures: provider, keys, client
│
└── examples/
    ├── modules/         # One standalone module per auth package
    │   ├── basic/       # authcore initialisation strategies
    │   ├── jwt/         # JWT: create, verify, rotate
    │   ├── password/    # Password: policy, hash, verify
    │   ├── email/       # Email: validate, normalize, DNS MX verification
    │   ├── username/    # Username: validate, normalize, reserved names
    │   ├── apikey/      # API keys: generate, verify, parse
    │   └── oauth/       # Social login: OIDC + OAuth2 flow
    ├── frameworks/      # Full auth APIs (separate modules)
    │   ├── fiber/       # Fiber v3
    │   └── gin/         # Gin
    └── deploy/
        └── containers/  # Container recipe
```

| Import path | Visibility | Purpose |
|---|---|---|
| `github.com/Glyndor/authcore` | public | Core types and entry point |
| `…/auth/jwt` | public | JWT module |
| `…/auth/password` | public | Argon2id password hashing module |
| `…/auth/email` | public | Email validation, normalization, MX verification |
| `…/auth/username` | public | Username validation, normalization, reserved names |
| `…/auth/apikey` | public | Opaque API key generation and verification |
| `…/auth/oauth` | public | OpenID Connect / OAuth2 client |
| `…/auth/totp` | public | TOTP second factor and recovery codes |
| `…/auth/credential` | public | Purpose-bound tokens for password reset and activation |
| `…/auth/field` | public | Column encryption and blind index |
| `…/internal/clock` | internal | Shared time abstraction |
| `…/internal/keystore/contract`, `/keysdir`, `/disk` | internal | KeyStore contract checks, keys directory checks, the disk loader |
| `…/internal/logging` | internal | Built-in stdlib and noop loggers |
| `…/internal/keymanager` | internal | Key generation and persistence |

## CI selection

I keep the root Go CI unconditional: its formatting check also reads nested Go
sources, and `tests/meta` inspects documentation, workflows and fuzz wiring.
Root lint, security audit and portability skip changes confined to the standalone
example modules. The Examples workflow builds and tests those modules instead.

I select all ten examples when any workspace member's `go.mod` or `go.sum`
changes, because dependency resolution is shared through `examples/go.work`.
Source and test changes inside one example select that example. Library test
changes alone do not select consumers: those builds do not run dependency tests.

The container recipe keeps workspace files and every example module's dependency
files as inputs, along with its own sources, deployment files and guide. Go
sources under `examples/modules` and `examples/frameworks` alone skip the recipe.
The repeated hostile run skips `tests/meta/*_test.go`; its own tests, fixtures
and production helpers remain eligible. Unclassified Go inputs stay eligible.

Pull requests into `main` run every selector-controlled check. Failed or uncertain
decisions retain the existing run policy. I exercise the workflow filters and
example matrix against real diffs with:

```bash
bash scripts/ci-decide/decide.test.sh
```
